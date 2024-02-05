
rule Trojan_Win32_Matsnu_W{
	meta:
		description = "Trojan:Win32/Matsnu.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 66 8b f6 4e 46 66 8b f6 4e 46 66 8b f6 4e 46 8b 91 b8 00 } //01 00 
		$a_01_1 = {00 00 49 41 49 41 4e 46 49 41 49 41 4e 46 b8 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}