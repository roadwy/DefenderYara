
rule Trojan_Win32_Zesy_RDA_MTB{
	meta:
		description = "Trojan:Win32/Zesy.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 c8 8b 08 c1 e9 08 89 4d b4 8b 4d cc 33 4d b4 8b 45 d4 33 d2 f7 75 ac 8b 45 08 03 0c 90 90 89 4d cc 8b 0d 90 01 04 33 d2 89 4d 80 89 55 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}