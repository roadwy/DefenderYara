
rule Trojan_BAT_Heracles_NM_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 5d 08 58 08 5d 91 11 06 61 11 05 17 58 08 5d 08 58 08 5d } //2
		$a_81_1 = {48 75 6d 61 6e 73 48 61 6e 64 46 6f 72 6d 5f 4c 6f 61 64 } //1 HumansHandForm_Load
		$a_81_2 = {42 6c 61 63 6b 6a 61 63 6b 33 } //1 Blackjack3
		$a_81_3 = {42 6c 61 63 6b 6a 61 63 6b 33 2e 53 63 6f 72 65 62 6f 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //1 Blackjack3.Scoreboard.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}