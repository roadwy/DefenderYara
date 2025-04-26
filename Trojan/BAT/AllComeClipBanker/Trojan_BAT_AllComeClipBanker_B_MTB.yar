
rule Trojan_BAT_AllComeClipBanker_B_MTB{
	meta:
		description = "Trojan:BAT/AllComeClipBanker.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 07 03 11 07 91 13 08 16 16 11 08 8c ?? 00 00 01 11 06 8c ?? 00 00 01 18 28 ?? ?? 00 06 13 09 28 ?? ?? 00 06 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0a 06 74 ?? 00 00 1b 11 04 16 16 11 0a 8c ?? 00 00 01 11 09 8c ?? 00 00 01 18 28 ?? ?? 00 06 b4 9c 11 04 17 d6 13 04 } //2
		$a_01_1 = {54 6f 49 6e 74 65 67 65 72 } //1 ToInteger
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}