
rule Trojan_Win64_MalLoadz_A_MTB{
	meta:
		description = "Trojan:Win64/MalLoadz.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 89 45 fc 8b 4d 08 0f be 11 03 55 fc 89 55 fc 8b 45 08 83 c0 01 89 45 08 8b 4d 08 0f be } //1
		$a_01_1 = {41 0f b6 11 4d 8d 49 01 41 0f b6 ca 41 ff ca 80 e1 03 d2 ca 42 8d 04 01 32 d0 41 88 51 ff 49 83 eb 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}