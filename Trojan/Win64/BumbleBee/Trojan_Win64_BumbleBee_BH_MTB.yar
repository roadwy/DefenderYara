
rule Trojan_Win64_BumbleBee_BH_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 00 48 33 c1 48 89 84 24 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 99 48 8b 8c 24 ?? ?? 00 00 f7 39 48 8b 8c 24 ?? ?? 00 00 89 01 } //2
		$a_03_1 = {48 03 c8 48 8b c1 48 89 84 24 ?? 00 00 00 48 8b 44 24 ?? 0f bf 00 0f bf 4c 24 ?? 33 c1 48 8b 4c 24 ?? 66 89 01 48 } //2
		$a_81_2 = {6c 57 36 7a 5c 4d 61 63 68 6f 70 6f 6c 79 70 5c 43 6f 79 69 73 68 5c 38 6a 46 6d 67 6b 5c 64 51 } //1 lW6z\Machopolyp\Coyish\8jFmgk\dQ
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}