
rule Trojan_Win64_Convagent_NL_MTB{
	meta:
		description = "Trojan:Win64/Convagent.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 60 48 8d 6c 24 ?? 48 89 4d f0 48 89 55 f8 48 8d 45 f0 48 89 45 c0 48 c7 45 c8 01 00 00 00 48 c7 45 d0 08 00 00 00 0f 57 c0 0f 11 45 d8 4c 8d 05 28 34 11 00 48 8d 4d c0 31 d2 e8 0d ff ff ff } //2
		$a_03_1 = {8b 45 f8 48 8b 50 08 48 85 d2 74 0d 4c 8b 40 10 48 8b 4d e8 e8 79 4c ad ff ba ?? 00 00 00 41 b8 ?? 00 00 00 48 8b 4d e0 e8 65 4c ad ff 31 c0 48 83 c4 48 5e 5d } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}