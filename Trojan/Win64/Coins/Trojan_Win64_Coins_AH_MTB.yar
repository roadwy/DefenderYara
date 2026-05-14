
rule Trojan_Win64_Coins_AH_MTB{
	meta:
		description = "Trojan:Win64/Coins.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 4c 32 40 77 51 35 24 70 58 38 7a 52 31 6d 4b 34 63 46 37 68 4a 30 65 54 33 79 55 36 69 4f 39 61 53 32 64 47 35 66 48 38 6a 4b 31 6c 5a 34 78 43 37 76 42 30 6e 4d 33 71 57 36 74 59 39 } //20 nL2@wQ5$pX8zR1mK4cF7hJ0eT3yU6iO9aS2dG5fH8jK1lZ4xC7vB0nM3qW6tY9
		$a_01_1 = {48 33 c1 48 89 45 00 48 8b 45 08 48 89 45 08 48 8b 45 08 48 8b 4d 00 48 33 c8 48 89 4d 00 eb } //30
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}