
rule Trojan_Win64_Trickbot_ZY{
	meta:
		description = "Trojan:Win64/Trickbot.ZY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 f8 48 3b 45 f0 73 28 48 8b 45 18 0f b6 00 66 98 48 8b 55 f8 66 89 02 48 8b 45 18 0f b6 00 84 c0 74 0c 48 83 45 f8 02 48 83 45 18 01 eb cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}