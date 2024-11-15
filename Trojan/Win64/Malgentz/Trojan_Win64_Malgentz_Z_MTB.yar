
rule Trojan_Win64_Malgentz_Z_MTB{
	meta:
		description = "Trojan:Win64/Malgentz.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 67 e6 09 6a 85 ae 67 bb 48 89 01 48 b8 72 f3 6e 3c 3a f5 4f a5 48 89 41 08 48 b8 7f 52 0e 51 8c 68 05 9b 48 89 41 10 48 b8 ab d9 83 1f 19 cd e0 5b 48 89 41 18 } //1
		$a_01_1 = {31 c0 4c 89 e7 48 89 e9 f2 ae 48 89 f7 48 f7 d1 48 8d 14 29 48 89 e9 89 94 24 80 00 00 00 f2 ae 4c 89 ef 48 f7 d1 4c 8d 04 29 48 89 e9 44 89 84 24 84 00 00 00 f2 ae 48 89 c8 48 f7 d0 48 01 c5 4d 85 c0 89 ac 24 88 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}