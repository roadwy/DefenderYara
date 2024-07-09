
rule Backdoor_Win64_Bazarldr_MFK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 60 41 b9 [0-04] 44 8b c0 33 c9 ff 15 [0-04] 48 8b f8 44 8b 44 24 [0-01] 48 8b d6 48 8b c8 e8 [0-03] 00 } //1
		$a_03_1 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-01] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4 } //1
		$a_03_2 = {8b 06 48 8b 4c 24 [0-01] 45 33 c9 89 44 24 [0-01] 45 8d 41 [0-01] 33 d2 48 89 74 24 [0-01] 48 89 6c 24 [0-01] ff 15 [0-04] 85 c0 0f 95 c0 eb bd } //1
		$a_01_3 = {6d 67 7a 4a 67 23 3c 58 67 6c 30 41 21 69 2b } //1 mgzJg#<Xgl0A!i+
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}