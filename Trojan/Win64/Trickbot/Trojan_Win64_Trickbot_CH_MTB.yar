
rule Trojan_Win64_Trickbot_CH_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 b9 03 00 00 00 48 8b d8 c7 ?? 45 6e 74 65 c7 ?? ?? 72 20 74 6f c7 ?? ?? 20 43 6f 6e c7 ?? ?? 74 72 6f 6c 66 c7 ?? ?? 0a 00 } //1
		$a_03_1 = {48 8b d8 c7 ?? 4d 6f 64 75 c7 ?? ?? 6c 65 20 68 c7 ?? ?? 61 6e 64 6c c7 ?? ?? 65 20 30 78 c7 ?? ?? 25 30 38 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}