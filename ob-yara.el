;;; ob-yara.el --- Babel Functions for Yara          -*- lexical-binding: t; -*-

;; Copyright (C) 2021 Mo Lee <github.com/limoiie>

;; Author: Mo Lee <limo.iie4@gmail.com>
;; Homepage https://github.com/limoiie/ob-yara
;; Created: 14th November 2021
;; Keywords: yara language org babel
;; Version: 0.01
;; Package-Requires: ((org "8"))

;;; License:

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3, or (at your option)
;; any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
;; Boston, MA 02110-1301, USA.

;;; Commentary:

;; Execute yara rule within org-mode source blocks with org-babel.
;;
;; ob-yara adds the support for the yara language to org-babel in the org-mode.
;; Yara is a tool for identifying and classifying malware samples by defining
;; corresponding rules written in yara language. Each rule consistes of a set of
;; strings and a boolean expression which determine its logic. With ob-yara,
;; you can evaluate the source code block of yara in an org file on the fire.

;; Here is an example in an org file:
;;
;; #+begin_src yara :target /bin/curl :cmd-line -s :var filesize=10
;;   rule Hello {
;;     strings:
;;       $a = "hello"
;;     condition:
;;       $a and filesize > 10
;;   }
;; #+end_src
;;
;; Move the cursor to above code block, then tap 'ctrl+c, ctrl+c' to eval the
;; code block. That actually equals to run the following shell command:
;;
;; $ yara $rule-file /bin/curl -d=filesize=10 -s
;;
;; , where $rule-file is a file containing the code block mentioned above.

;;; Requirements:

;; - you must have the yara tool installed in your os and the yara binary
;;   should be in the PATH environment variable.
;; - org-8 with org-babel

;;; Code:
(require 'ob)
(require 'ob-ref)
(require 'ob-eval)

;; define a file extension for yara language
(defvar org-babel-tangle-lang-exts)
(add-to-list 'org-babel-tangle-lang-exts '("yara" . "yara"))

;; declare default header arguments for this language
(defvar org-babel-default-header-args:yara '((:print-strings . t)))

(defun org-babel-expand-body:yara (body _params &optional _processed_params)
  "Expand BODY according to PARAMS, return the expanded body."
     body)

;;;###autoload
(defun org-babel-execute:yara (body params)
  "Execute a block of yara code with org-babel.
This function is called by `org-babel-execute-src-block'. It will evaluate the
body of the source code and return the results as emacs-lisp."
  (message "executing Yara source code block")
  (let* ((processed-params (org-babel-process-params params))
         (result-params (assq :result-params processed-params))
         ;; expand the body with `org-babel-expand-body:yara'
         (full-body (org-babel-expand-body:yara
                     body params processed-params))
         ;; fill the source code block into a temp file
         (rule-file (let ((file (org-babel-temp-file "yara-")))
                      (with-temp-file file (insert full-body)) file))
         (processed-params (cons `(:rule . ,rule-file) processed-params))
         ;; reassemble params into a command line
         (yara-executable (list "yara"))
         (cmd-parts (append
                     yara-executable
                     (org-babel-yara-vars-in-cmd-line processed-params)
                     (org-babel-yara-options-in-cmd-line processed-params)))
         (cmd (mapconcat #'identity (remove "" cmd-parts) " ")))
    (message "cmd: `%s'" cmd)
    (let ((results (org-babel-eval cmd "")))
      (org-babel-yara-table-or-string results result-params processed-params))))

(defun org-babel-yara-vars-in-cmd-line (params)
  "Convert PARAMS to yara command line format."
  (mapcar (lambda (pair)
            (format "--define=%s=%s"
                    (car pair)
                    (org-babel-yara-var-to-yara
                     (cdr pair))))
          (org-babel-yara--get-all-by-key :var params)))

(defun org-babel-yara-options-in-cmd-line (params)
  "Convert PARAMS to yara command line format."
  (let ((opts `(;; original yara command-line options
                (:compiled-rules "--compiled-rules" bool)
                (:count "--count" bool)
                (:fast-scan "--fast-scan" bool)
                (:identifier "--identifier" string)
                (:max-rules "--max-rules" number)
                (:module-data "--module-data" string)
                (:timeout "--timeout" integer)
                (:threads "--threads" integer)
                (:negate "--negate" bool)
                (:no-warnings "--no-warnings" bool)
                (:print-meta "--print-meta" bool)
                (:print-module-data "--print-module-data" bool)
                (:print-namespace "--print-namespace" bool)
                (:print-stats "--print-stats" bool)
                (:print-strings "--print-strings" bool)
                (:print-string-length "--print-string-length" bool)
                (:print-tags "--print-tags" bool)
                (:recursive "--recursive" bool)
                (:scan-list "--scan-list" string)
                (:tag "--tag" string)
                ;; additional options
                (:cmd-line nil no-key-string) ; additional command-line options
                (:rule nil no-key-string multiple)
                ;; for following keys, only one of them can be specified at once
                (:in-file nil no-key-string)
                (:in-dir nil no-key-string)
                (:in-pid nil no-key-integer))))
    (apply #'append
           (mapcar
            (lambda (opt)
              (let* ((multi-key (nth 3 opt))
                     (opt-val-list
                      (if (equal multi-key 'multiple)
                          (org-babel-yara--get-all-by-key (car opt) params)
                        (org-babel-yara--get-one-by-key (car opt) params)))
                     (opt-key (nth 1 opt))
                     (val-typ (nth 2 opt)))
                (mapcar
                 (lambda (opt-val)
                   (cond
                    ((not opt-val) "")
                    ((equal val-typ 'bool) opt-key)
                    ((equal val-typ 'string) (format "%s=%s" opt-key opt-val))
                    ((equal val-typ 'integer) (format "%s=%d" opt-key opt-val))
                    ((equal val-typ 'no-key-string) opt-val)
                    ((equal val-typ 'no-key-integer) (format "%d" opt-val))
                    (t (format "%s=%s" opt-key opt-val))))
                 opt-val-list)
                ))
            opts))))

(defun org-babel-yara-var-to-yara (var)
  "Convert an elisp var into a string of yara source code
specifying a var of the same value."
  (format "%S" var))

(defun org-babel-yara-table-or-string (results result-params params)
  "If the results look like a table, then convert them into an
Emacs-lisp table, otherwise return the results as a string."
  (org-babel-reassemble-table
   (when results
     (org-babel-result-cond result-params
       results
       (let ((tmp (org-babel-temp-file "yara-results-")))
         (with-temp-file tmp (insert results))
         (org-babel-import-elisp-from-file tmp))))
   (org-babel-pick-name
    (cdr (assq :colname-names params)) (cdr (assq :colnames params)))
   (org-babel-pick-name
    (cdr (assq :rowname-names params)) (cdr (assq :rownames params))))
  results)

(defun org-babel-yara--get-all-by-key (key params)
  "Return the babel header options by KEY in PARAMS.

PARAMS is a quasi-alist of header args, which may contain
multiple entries for the key `key'.  This function returns a
list of the cdr of all the `key' entries."
  (mapcar #'cdr
	        (cl-remove-if-not (lambda (x) (eq (car x) key)) params)))

(defun org-babel-yara--get-one-by-key (key params)
  "Return the babel header option by KEY in PARAMS.

PARAMS is a quasi-alist of header args, which may contain
multiple entries for the key `key'.  This function returns a
list of the cdr of the first `key' entry."
  (list (cdr (assq key params))))

;;;###autoload
(eval-after-load "org"
  '(add-to-list 'org-src-lang-modes '("yara" . yara)))

(provide 'ob-yara)
;;; ob-yara.el ends here
