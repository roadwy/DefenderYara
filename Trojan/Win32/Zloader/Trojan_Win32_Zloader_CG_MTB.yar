
rule Trojan_Win32_Zloader_CG_MTB{
	meta:
		description = "Trojan:Win32/Zloader.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0c 03 8b 54 03 04 33 4d 08 33 55 0c 09 ca 75 } //01 00 
		$a_01_1 = {f7 e1 0f af f9 01 da 01 d7 8b 55 d4 29 c2 19 fe 81 c2 } //00 00 
	condition:
		any of ($a_*)
 
}