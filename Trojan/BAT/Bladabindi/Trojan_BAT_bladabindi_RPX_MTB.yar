
rule Trojan_BAT_bladabindi_RPX_MTB{
	meta:
		description = "Trojan:BAT/bladabindi.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 5f 91 fe 09 02 00 60 61 d1 9d fe 0c 00 00 ?? ?? ?? ?? ?? 20 02 00 00 00 63 66 20 01 00 00 00 63 66 65 20 04 00 00 00 62 ?? ?? ?? ?? ?? 58 66 ?? ?? ?? ?? ?? 59 59 25 fe 0e 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}