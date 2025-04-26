
rule Trojan_Win64_CobaltStrike_NC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 53 56 48 83 ec 48 45 8b d0 8d 99 ac fd ff ff 41 81 f2 d9 03 00 00 8d 83 1f 03 00 00 44 8d 9a b5 fa ff ff 8b f1 44 3b d0 } //2
		$a_01_1 = {eb 4c 8b c5 25 c1 13 00 00 41 03 c0 3b f0 74 3e } //1
		$a_81_2 = {4d 74 64 6b 76 73 51 47 7a 43 76 4a } //1 MtdkvsQGzCvJ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}