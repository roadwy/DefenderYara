
rule Trojan_Win64_BazarLoader_M_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {44 8d 34 13 f7 eb 41 c1 fe 05 8b c2 41 8b ce c1 f8 04 c1 e9 1f 44 03 f1 8b c8 c1 e9 1f 03 c1 89 44 24 28 } //10
		$a_81_1 = {63 7a 61 63 65 73 6e 6f 7a 78 76 67 2e 64 6c 6c } //3 czacesnozxvg.dll
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}