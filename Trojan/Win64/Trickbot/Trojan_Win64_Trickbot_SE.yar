
rule Trojan_Win64_Trickbot_SE{
	meta:
		description = "Trojan:Win64/Trickbot.SE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 48 89 56 70 4c 89 46 78 4c 89 8e 80 00 00 00 } //1
		$a_01_1 = {8b c9 48 89 8e 88 00 00 00 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20 } //1
		$a_01_2 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 4c 89 8e 80 00 00 00 8b c9 } //1
		$a_01_3 = {48 89 8e 88 00 00 00 48 89 56 70 4c 89 46 78 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}