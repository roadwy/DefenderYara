
rule Trojan_Win32_Glupteba_KA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {81 ec 1c 04 00 00 a1 90 01 04 33 c4 89 84 24 18 04 00 00 a1 90 01 04 53 55 56 57 8b 3d 90 01 04 33 db a3 90 01 04 33 f6 8d 64 24 00 81 3d 90 01 04 c7 01 00 00 75 29 90 00 } //0a 00 
		$a_02_1 = {81 fe cc 6b 84 00 75 0b b8 15 00 00 00 01 05 90 01 04 46 81 fe c5 0a 26 01 7c af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}