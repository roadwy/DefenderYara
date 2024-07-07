
rule Ransom_Win32_Locky_GJU_MTB{
	meta:
		description = "Ransom:Win32/Locky.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {da f9 6d 9e c7 85 90 01 04 57 4b 8c 88 c7 85 90 01 04 57 4b 8c 88 c7 85 90 01 04 19 c8 f1 26 c7 85 90 01 04 cb 47 57 0c 90 00 } //5
		$a_01_1 = {57 30 43 75 33 61 68 58 34 79 } //5 W0Cu3ahX4y
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}