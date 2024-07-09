
rule Trojan_BAT_Aurora_ABTJ_MTB{
	meta:
		description = "Trojan:BAT/Aurora.ABTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 06 16 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 72 f6 11 00 70 06 07 28 ?? 00 00 0a 0c 08 72 1c 12 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0d 72 0f 00 00 70 13 04 02 2c 23 02 8e 69 17 33 1d } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {47 65 74 53 63 72 69 70 74 42 6c 6f 63 6b } //1 GetScriptBlock
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}