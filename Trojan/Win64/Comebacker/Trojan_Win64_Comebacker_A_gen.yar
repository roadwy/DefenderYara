
rule Trojan_Win64_Comebacker_A_gen{
	meta:
		description = "Trojan:Win64/Comebacker.A.gen!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 fb ff ff ff eb 1b b8 fb ff ff ff 41 bd 01 00 00 00 85 c9 44 0f 45 e8 41 8b c5 eb 05 b8 fd ff ff ff } //1
		$a_01_1 = {48 8b 4d e0 ff 55 d8 33 c0 eb 05 b8 fc ff ff ff 4c 8d 9c 24 80 00 00 00 49 8b 5b 10 49 8b 7b 18 49 8b e3 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}