
rule Trojan_Win32_Salgorea_VRR_MTB{
	meta:
		description = "Trojan:Win32/Salgorea.VRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {7b 45 35 44 38 41 43 46 46 2d 36 45 39 38 2d 34 38 38 32 2d 41 39 39 41 2d 45 43 43 41 46 42 45 38 34 34 38 43 7d 2a 31 39 34 37 61 62 38 64 30 61 32 37 62 35 63 61 65 63 38 30 36 62 39 38 38 66 30 65 65 32 64 61 2a } //01 00  {E5D8ACFF-6E98-4882-A99A-ECCAFBE8448C}*1947ab8d0a27b5caec806b988f0ee2da*
		$a_01_1 = {57 65 74 75 63 65 78 45 6c 6c 65 68 53 } //01 00  WetucexEllehS
		$a_01_2 = {61 4e 72 65 74 75 70 6d 6f 43 74 65 47 6d 65 57 } //00 00  aNretupmoCteGmeW
	condition:
		any of ($a_*)
 
}