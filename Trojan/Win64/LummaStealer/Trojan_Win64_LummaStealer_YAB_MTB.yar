
rule Trojan_Win64_LummaStealer_YAB_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 0f b6 44 3e 01 0f b6 4c 05 30 43 0f b6 44 3e 02 0f b6 54 05 30 43 0f b6 44 3e 03 44 0f b6 44 05 30 49 83 c6 04 c1 e7 06 03 f9 c1 e7 06 03 fa c1 e7 06 41 03 f8 } //1
		$a_01_1 = {44 30 27 48 ff c7 49 83 ef 01 0f 85 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}