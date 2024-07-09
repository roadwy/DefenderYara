
rule Trojan_BAT_ExMatter_MA_MTB{
	meta:
		description = "Trojan:BAT/ExMatter.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 2b 01 16 0c 08 2c 05 00 17 0d de 16 00 16 0d de 11 26 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 00 16 0d de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}