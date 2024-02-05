
rule Trojan_Win32_Emotet_DCN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {33 d2 f7 f1 8b 45 90 01 01 33 c9 66 8b 0c 50 51 90 02 0a 50 90 13 55 8b ec 8b 45 90 01 01 0b 45 90 01 01 8b 4d 90 01 01 f7 d1 8b 55 90 01 01 f7 d2 0b ca 23 c1 5d 90 00 } //01 00 
		$a_02_1 = {33 c0 33 d2 8a 06 8a 17 03 c2 b9 90 01 04 99 f7 f9 8b 35 90 01 04 83 c4 90 01 01 33 c0 6a 00 90 00 } //01 00 
		$a_00_2 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 } //00 00 
	condition:
		any of ($a_*)
 
}