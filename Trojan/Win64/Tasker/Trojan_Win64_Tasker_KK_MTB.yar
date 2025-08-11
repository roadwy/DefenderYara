
rule Trojan_Win64_Tasker_KK_MTB{
	meta:
		description = "Trojan:Win64/Tasker.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 01 00 00 00 f0 48 0f c1 0d ?? ?? 16 00 49 89 cf 4d 31 c7 4c 89 fb 48 c1 c3 10 4f 8d 24 0f 4c 31 e3 4e 8d 2c 13 4c 31 e9 4d 01 df 4d 89 fc 49 c1 c4 20 48 c1 c3 15 4d 31 f7 } //10
		$a_03_1 = {48 89 44 24 30 48 8d 84 24 78 01 00 00 ?? ?? ?? 24 20 48 c7 44 24 38 00 00 00 00 c7 44 24 28 0c 00 00 00 48 89 f1 ba 00 14 2d 00 4c 8d 84 24 b4 01 00 00 41 b9 0c 00 00 00 e8 } //5
		$a_01_2 = {63 6d 64 2f 43 73 63 68 74 61 73 6b 73 2f 43 72 65 61 74 65 2f 53 43 4f 4e 4c 4f 47 4f 4e 2f 54 4e 2f 54 52 2f 52 4c 48 49 47 48 45 53 54 2f 46 } //7 cmd/Cschtasks/Create/SCONLOGON/TN/TR/RLHIGHEST/F
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_01_2  & 1)*7) >=22
 
}