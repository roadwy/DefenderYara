
rule Backdoor_Linux_Gafgyt_DD_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.DD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 83 ec 08 8b 5c 24 14 ff 74 24 18 ff 73 04 ff 33 8b 44 24 1c ff 70 04 e8 f7 df ff ff 83 c4 10 85 d2 89 c1 78 ?? 89 03 31 c9 89 53 04 } //1
		$a_03_1 = {0f b1 4b 38 0f 85 a1 00 00 00 89 53 40 ff 43 3c f6 03 40 74 ?? 83 ec 0c 53 e8 22 b2 ff ff 83 c4 10 85 c0 75 ?? 83 ff 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}