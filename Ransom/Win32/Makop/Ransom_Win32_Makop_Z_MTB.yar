
rule Ransom_Win32_Makop_Z_MTB{
	meta:
		description = "Ransom:Win32/Makop.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 18 83 c4 0c 8b 4f 0c 03 c6 50 8d 54 24 18 52 51 6a 00 6a 00 89 44 24 28 8b 44 24 3c } //1
		$a_01_1 = {20 00 75 15 8b 44 24 10 8b 4c 24 08 8b 54 24 0c 89 46 20 89 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}