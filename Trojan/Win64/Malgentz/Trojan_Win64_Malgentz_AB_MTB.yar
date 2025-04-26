
rule Trojan_Win64_Malgentz_AB_MTB{
	meta:
		description = "Trojan:Win64/Malgentz.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 02 00 00 00 48 b8 02 01 25 1d 12 2c 16 5e 48 89 44 24 30 48 b8 06 f2 25 03 16 ff 7f 0f 48 89 44 24 38 48 8d 44 24 28 48 8b f8 33 c0 b9 08 00 00 00 } //1
		$a_01_1 = {89 44 24 30 8b 44 24 30 48 69 c0 20 04 00 00 48 63 4c 24 38 48 8b 94 24 d8 00 00 00 48 03 8c 02 10 04 00 00 48 8b c1 b9 04 00 00 00 48 6b c9 00 48 8b d0 48 8b 84 24 d0 00 00 00 8b 0c 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}