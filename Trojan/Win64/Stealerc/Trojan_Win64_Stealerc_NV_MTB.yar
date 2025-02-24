
rule Trojan_Win64_Stealerc_NV_MTB{
	meta:
		description = "Trojan:Win64/Stealerc.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 1d 4b b8 2b 00 33 f6 f6 03 02 74 ?? 48 8b 7b 10 eb ?? 45 33 c9 4c 8d 44 24 58 48 8d 15 6f b4 22 00 48 8b cb e8 ?? ?? ?? ?? 84 c0 48 8b } //3
		$a_01_1 = {73 74 65 61 6c 65 72 5f 62 6f 74 } //1 stealer_bot
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}