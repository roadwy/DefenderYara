
rule Trojan_Win64_InjectorX_CS_MTB{
	meta:
		description = "Trojan:Win64/InjectorX.CS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c2 0f b6 d2 0f b6 9c 15 a0 00 00 00 40 00 de 40 02 b4 15 b0 01 00 00 44 0f b6 d6 42 0f b6 84 15 a0 00 00 00 88 84 15 a0 00 00 00 42 88 9c 15 a0 00 00 00 02 9c 15 a0 00 00 00 0f b6 c3 0f b6 84 05 a0 00 00 00 41 30 04 38 48 ff c7 49 39 fe } //1
		$a_01_1 = {63 6f 6d 70 75 74 65 72 68 6f 6c 6f 63 61 75 73 74 } //1 computerholocaust
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}