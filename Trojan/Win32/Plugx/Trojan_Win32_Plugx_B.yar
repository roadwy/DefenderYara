
rule Trojan_Win32_Plugx_B{
	meta:
		description = "Trojan:Win32/Plugx.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {c6 06 e9 88 4e 90 03 01 01 02 03 90 00 } //01 00 
		$a_00_1 = {6a ff ff d6 6a ff ff d6 6a ff ff d6 } //01 00 
		$a_01_2 = {4e 76 53 6d 61 72 74 } //00 00  NvSmart
	condition:
		any of ($a_*)
 
}