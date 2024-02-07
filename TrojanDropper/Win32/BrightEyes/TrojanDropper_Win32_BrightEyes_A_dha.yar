
rule TrojanDropper_Win32_BrightEyes_A_dha{
	meta:
		description = "TrojanDropper:Win32/BrightEyes.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 4d 6f 64 75 6c 65 20 70 72 6f 78 79 5f 63 67 69 5f 6d 6f 64 75 6c 65 20 6d 6f 64 75 6c 65 73 2f 6d 6f 64 5f 70 72 6f 78 79 5f 63 67 69 2e 73 6f } //02 00  LoadModule proxy_cgi_module modules/mod_proxy_cgi.so
		$a_01_1 = {2f 69 6e 64 65 78 2f 69 6e 63 31 75 64 65 2f 63 6f 6e 6e 2f } //01 00  /index/inc1ude/conn/
		$a_01_2 = {2d 00 75 00 00 00 00 00 2d 00 55 00 00 00 00 00 2d 00 69 00 00 00 00 00 2d 00 49 00 00 00 00 00 } //02 00 
		$a_01_3 = {78 63 70 6f 79 20 25 73 20 25 73 20 2f 45 20 2f 59 } //01 00  xcpoy %s %s /E /Y
		$a_01_4 = {72 64 20 2f 53 20 2f 51 20 25 73 } //01 00  rd /S /Q %s
		$a_01_5 = {25 73 20 53 50 25 64 20 28 42 75 69 6c 64 20 25 64 29 20 25 73 } //03 00  %s SP%d (Build %d) %s
		$a_01_6 = {5c 70 72 6f 6a 65 63 74 5c 6f 77 6c 5c 69 73 61 70 69 5c } //00 00  \project\owl\isapi\
	condition:
		any of ($a_*)
 
}