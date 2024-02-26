
rule Ransom_MSIL_Mallox_MB_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 9d b6 3d 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c2 00 00 00 33 } //01 00 
		$a_01_1 = {30 30 64 61 31 32 30 36 2d 61 66 65 36 2d 34 63 34 61 2d 61 38 38 66 2d 35 66 66 30 36 63 61 37 30 30 64 30 } //01 00  00da1206-afe6-4c4a-a88f-5ff06ca700d0
		$a_01_2 = {62 36 32 37 37 39 34 36 63 63 63 34 37 63 2e 52 65 73 6f 75 72 63 65 73 } //00 00  b6277946ccc47c.Resources
		$a_00_3 = {5d 04 00 } //00 0a 
	condition:
		any of ($a_*)
 
}