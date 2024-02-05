
rule Trojan_Win32_Zusy_CE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b f0 33 d6 03 ca 8b 15 90 02 04 03 95 90 02 04 88 0a 90 00 } //01 00 
		$a_03_1 = {23 d0 33 ca 88 8d 90 02 04 0f b6 8d 90 02 04 03 8d 90 02 04 0f b6 95 90 02 04 83 c2 90 02 04 33 ca 88 8d 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}