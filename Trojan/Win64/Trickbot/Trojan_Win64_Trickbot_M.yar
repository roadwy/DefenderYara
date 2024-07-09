
rule Trojan_Win64_Trickbot_M{
	meta:
		description = "Trojan:Win64/Trickbot.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 01 75 [0-40] 8b ?? 41 33 ?? 89 ?? 48 83 ?? 04 49 83 ?? 04 48 83 ?? 04 49 3b ?? 49 0f 43 ?? 4d 3b ?? 72 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}