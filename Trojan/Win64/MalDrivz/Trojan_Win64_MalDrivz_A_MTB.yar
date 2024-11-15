
rule Trojan_Win64_MalDrivz_A_MTB{
	meta:
		description = "Trojan:Win64/MalDrivz.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 10 c1 e2 10 41 0f bf 09 81 c2 00 80 00 00 41 03 d3 03 d1 c1 fa 10 66 41 89 10 } //1
		$a_01_1 = {41 0f b7 00 c1 e0 10 41 03 c3 c1 f8 10 66 41 89 00 } //1
		$a_01_2 = {41 8b 10 8b c2 25 ff ff ff 03 41 8d 0c 83 c1 f9 02 33 ca 81 e1 ff ff ff 03 33 ca 41 89 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}