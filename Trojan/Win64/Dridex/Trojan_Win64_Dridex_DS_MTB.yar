
rule Trojan_Win64_Dridex_DS_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {be 7a 39 86 47 48 8b 0d 90 02 04 bf e2 2f cf c4 ba 41 6a 06 a2 41 b8 7a 39 86 47 48 89 4c 24 38 89 f9 4c 8b 4c 24 38 89 44 24 34 44 89 54 24 30 44 89 5c 24 2c 89 74 24 28 41 ff d1 4c 8b 4c 24 78 48 8b 5c 24 60 49 01 d9 49 81 f9 63 3e 00 00 89 44 24 24 4c 89 8c 24 80 00 00 00 0f 84 90 00 } //2
		$a_03_1 = {48 8b 84 24 80 00 00 00 48 8b 0d 90 02 04 48 89 44 24 78 ff d1 48 8d 0d 90 02 04 48 8b 94 24 a0 00 00 00 48 81 f2 4f d6 a9 3a 4c 8d 05 90 00 } //2
		$a_01_2 = {54 00 63 00 4c 00 72 00 4e 00 68 00 59 00 4b 00 46 00 4b 00 64 00 6b 00 6d 00 58 00 74 00 6e 00 } //1 TcLrNhYKFKdkmXtn
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}