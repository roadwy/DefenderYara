
rule Trojan_Win64_CobaltStrike_YTB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 25 ff ff ff 3f 48 d1 e2 48 c1 ea 1f 48 be 80 7f b1 d7 0d 00 00 00 48 01 f2 48 89 54 24 30 48 89 44 24 28 } //1
		$a_81_1 = {39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 34 64 35 61 34 31 35 32 35 35 34 38 38 39 65 35 34 38 38 31 65 63 32 30 30 30 30 30 30 30 34 38 38 64 31 64 65 61 66 66 66 66 66 66 34 38 38 } //1 9090909090909090904d5a4152554889e54881ec20000000488d1deaffffff488
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}