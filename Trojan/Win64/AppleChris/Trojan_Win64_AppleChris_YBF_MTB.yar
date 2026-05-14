
rule Trojan_Win64_AppleChris_YBF_MTB{
	meta:
		description = "Trojan:Win64/AppleChris.YBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 4c 24 20 48 8d 05 24 fd ff ff 48 89 44 24 28 33 c0 48 89 44 24 30 48 89 44 24 38 ff 15 8d cf 15 00 b9 d0 07 00 00 ff 15 02 d1 15 00 eb f3 } //1
		$a_01_1 = {58 00 46 00 45 00 58 00 59 00 43 00 44 00 41 00 50 00 50 00 4c 00 45 00 30 00 35 00 43 00 48 00 52 00 49 00 53 } //1
		$a_01_2 = {3c 24 75 10 48 8b 54 24 40 48 8d 4d 51 e8 ed e1 ff ff eb 78 3c 25 75 10 48 8b 54 24 40 48 8d 4d 51 e8 89 ed ff ff eb 64 3c 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}