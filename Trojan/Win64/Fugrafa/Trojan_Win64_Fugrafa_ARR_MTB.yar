
rule Trojan_Win64_Fugrafa_ARR_MTB{
	meta:
		description = "Trojan:Win64/Fugrafa.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 38 32 4c 04 20 88 0c 18 ff c0 41 3b c0 72 } //12
		$a_03_1 = {44 33 cf 41 c1 c9 ?? 44 33 c5 41 c1 c8 ?? 47 8d 2c 0b 45 33 ea 41 c1 cd ?? 41 03 cd 41 } //8
	condition:
		((#a_01_0  & 1)*12+(#a_03_1  & 1)*8) >=20
 
}