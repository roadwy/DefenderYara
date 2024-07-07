
rule Trojan_BAT_ClipBanker_F_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 43 68 61 6e 67 65 72 } //2 StartChanger
		$a_01_1 = {54 65 6c 65 67 72 61 6d 2e 42 6f 74 } //2 Telegram.Bot
		$a_01_2 = {4d 61 69 6e 53 68 69 74 } //2 MainShit
		$a_01_3 = {52 65 67 65 78 2e 4d 61 74 63 68 28 47 65 74 54 65 78 74 } //2 Regex.Match(GetText
		$a_01_4 = {43 6f 6e 76 65 72 74 2e 54 6f 53 74 72 69 6e 67 28 50 61 74 74 65 72 6e 52 65 67 65 78 } //2 Convert.ToString(PatternRegex
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}