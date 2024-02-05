
rule Trojan_Win32_Enchanim_D{
	meta:
		description = "Trojan:Win32/Enchanim.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 38 06 00 01 40 74 90 01 01 8b 40 0c 80 38 ec 74 90 01 01 80 38 e4 74 90 01 01 80 38 ed 74 90 01 01 b8 00 00 00 00 90 00 } //01 00 
		$a_03_1 = {81 38 06 00 01 40 74 90 01 01 8b 48 0c 80 39 ec 0f 84 90 01 04 80 39 e4 74 90 01 01 80 39 ed 0f 84 90 01 04 80 39 f8 74 90 01 01 31 c9 90 00 } //04 00 
		$a_03_2 = {b2 7a 88 14 90 01 01 c1 ea 08 90 01 01 78 09 83 90 01 01 03 75 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}