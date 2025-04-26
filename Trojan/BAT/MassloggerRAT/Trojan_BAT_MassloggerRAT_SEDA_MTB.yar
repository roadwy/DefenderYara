
rule Trojan_BAT_MassloggerRAT_SEDA_MTB{
	meta:
		description = "Trojan:BAT/MassloggerRAT.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? ?? ?? 0a 9c 25 17 0f 00 28 ?? ?? ?? 0a 9c 25 18 0f 00 28 ?? ?? ?? 0a 9c 6f ?? ?? 00 0a 1b 13 } //1
		$a_03_1 = {58 12 02 28 ?? 00 00 0a 58 20 88 13 00 00 5d 20 e8 03 00 00 58 13 04 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*3) >=4
 
}