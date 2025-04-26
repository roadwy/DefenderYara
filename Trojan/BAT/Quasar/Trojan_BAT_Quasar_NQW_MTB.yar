
rule Trojan_BAT_Quasar_NQW_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 26 00 00 0a 0a 73 ?? ?? ?? 0a 0b 06 02 6f ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0d 07 6f ?? ?? ?? 0a 09 } //5
		$a_01_1 = {74 00 6d 00 70 00 36 00 31 00 37 00 31 00 2e 00 74 00 6d 00 70 00 } //1 tmp6171.tmp
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}