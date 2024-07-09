
rule Ransom_Win32_Tescrypt_YAB_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 02 29 f0 88 c1 88 4c 24 6f 8a 4c 24 } //1
		$a_03_1 = {66 8b 84 24 ?? ?? ?? ?? 66 33 84 24 ?? ?? ?? ?? 66 89 84 24 ?? ?? ?? ?? 8b 4c 24 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}