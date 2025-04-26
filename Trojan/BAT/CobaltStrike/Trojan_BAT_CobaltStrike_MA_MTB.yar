
rule Trojan_BAT_CobaltStrike_MA_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 08 25 11 07 11 08 11 08 8e 69 12 06 28 ?? ?? ?? 06 26 11 08 1f 3c 28 15 00 00 0a 1f 28 ?? ?? ?? 11 08 11 09 } //2
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 32 00 2e 00 39 00 32 00 2e 00 36 00 37 00 2e 00 39 00 37 00 } //5 http://182.92.67.97
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*5) >=7
 
}