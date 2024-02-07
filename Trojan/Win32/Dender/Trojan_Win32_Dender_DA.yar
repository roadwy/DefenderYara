
rule Trojan_Win32_Dender_DA{
	meta:
		description = "Trojan:Win32/Dender.DA,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 } //0a 00  /transfer 
		$a_00_1 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 } //0a 00  /download 
		$a_00_2 = {25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 6e 00 73 00 75 00 64 00 6f 00 2e 00 65 00 78 00 65 00 } //00 00  %temp%\nsudo.exe
	condition:
		any of ($a_*)
 
}