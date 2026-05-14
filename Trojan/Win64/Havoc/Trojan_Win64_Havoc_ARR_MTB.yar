
rule Trojan_Win64_Havoc_ARR_MTB{
	meta:
		description = "Trojan:Win64/Havoc.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c1 42 32 84 39 ?? ?? ?? ?? ?? ?? 88 44 0d 40 48 ff c1 48 3b ca } //12
		$a_01_1 = {0f b6 c8 48 8d 55 40 48 03 d0 48 ff c0 32 4c 17 } //8
	condition:
		((#a_03_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}