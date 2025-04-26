
rule Ransom_Win32_Stopcrypt_YAB_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 04 24 8b 44 24 ?? 31 04 24 8b 04 24 8b 4c 24 08 89 01 59 } //1
		$a_03_1 = {8b 4c 24 18 8d 34 17 d3 ea 03 d5 8b fa 8b 54 24 10 8d 04 1a 33 c6 81 3d ?? ?? ?? ?? 21 01 00 00 89 44 24 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}