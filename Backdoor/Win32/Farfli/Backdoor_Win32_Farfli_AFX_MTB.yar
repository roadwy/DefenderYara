
rule Backdoor_Win32_Farfli_AFX_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.AFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 8b 4c 24 14 47 03 c6 6a 00 8a 0c 0f 30 08 } //0a 00 
		$a_01_1 = {c6 45 f4 57 50 c6 45 f5 69 c6 45 f6 6e c6 45 f7 6c c6 45 f8 6f c6 45 f9 67 c6 45 fa 6f c6 45 fb 6e } //00 00 
	condition:
		any of ($a_*)
 
}