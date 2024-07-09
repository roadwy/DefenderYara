
rule Spyware_BAT_Keylogger_GB_MTB{
	meta:
		description = "Spyware:BAT/Keylogger.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 09 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 [0-04] 20 00 26 00 20 00 64 00 65 00 6c 00 } //10
		$a_02_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 30 20 2d 6e 20 [0-04] 20 26 20 64 65 6c } //10
		$a_80_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //netsh firewall add allowedprogram  10
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  10
		$a_80_4 = {53 45 45 5f 4d 41 53 4b 5f 4e 4f 5a 4f 4e 45 43 48 45 43 4b 53 } //SEE_MASK_NOZONECHECKS  10
		$a_80_5 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //netsh firewall delete allowedprogram  1
		$a_80_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_7 = {31 32 37 2e 30 2e 30 2e 31 } //127.0.0.1  1
		$a_80_8 = {5b 45 4e 54 45 52 5d } //[ENTER]  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=43
 
}