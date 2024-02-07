
rule Ransom_Win32_Phobos_PD_MTB{
	meta:
		description = "Ransom:Win32/Phobos.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 46 4c 58 4c 43 4c 46 4c 53 4d 43 56 4c 52 4c 58 } //04 00  OFLXLCLFLSMCVLRLX
		$a_03_1 = {c7 45 cc 00 00 00 00 81 7d cc 90 02 04 0f 83 90 02 04 8b 45 90 01 01 8b 4d 90 01 01 83 e1 90 01 01 0f be 04 08 8b 4d 90 01 01 0f b6 14 0d 90 02 04 31 c2 88 d3 88 1c 0d 90 02 04 8b 45 90 01 01 83 c0 01 89 45 90 01 01 e9 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 } //b4 bf 
	condition:
		any of ($a_*)
 
}