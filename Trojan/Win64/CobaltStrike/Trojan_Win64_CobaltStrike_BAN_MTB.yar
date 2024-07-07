
rule Trojan_Win64_CobaltStrike_BAN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 57 48 81 ec 38 01 00 00 48 8d ac 24 80 00 00 00 48 c7 45 a0 00 00 00 00 48 c7 45 a8 00 00 00 00 48 8d 55 b0 b8 00 00 00 00 b9 1e 00 00 00 48 89 d7 f3 48 ab 48 89 fa 89 02 48 83 c2 04 c7 85 ac 00 00 00 00 00 00 00 48 8d 45 a0 41 b8 04 01 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 90 01 04 ff d0 89 85 ac 00 00 00 83 bd ac 00 00 00 00 75 07 b8 00 00 00 00 eb 2d 48 8d 45 a0 48 8d 15 90 01 04 48 89 c1 e8 90 01 04 48 85 c0 75 07 b8 00 00 00 00 eb 0e 48 8d 05 90 01 04 ff d0 b8 01 00 00 00 48 81 c4 38 01 00 00 5f 5d c3 90 00 } //1
		$a_03_1 = {c7 00 00 00 00 00 e9 9e fe ff ff 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 48 89 ca 48 8d 0d 90 02 0b 48 8d 0d 09 00 00 00 e9 e4 ff ff ff 0f 1f 40 00 c3 90 00 } //1
		$a_01_2 = {43 6f 72 47 65 74 53 76 63 } //1 CorGetSvc
		$a_01_3 = {6d 73 63 6f 72 73 76 63 2e 64 6c 6c } //1 mscorsvc.dll
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}