
rule Trojan_BAT_Remcos_SKF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 02 03 06 04 28 42 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0b 07 2d d7 } //1
		$a_00_1 = {24 64 62 39 37 37 38 32 62 2d 31 39 37 61 2d 34 33 33 35 2d 38 36 38 61 2d 35 31 61 65 39 65 65 38 37 65 62 63 } //1 $db97782b-197a-4335-868a-51ae9ee87ebc
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}