
rule Trojan_BAT_LummaStealer_CCHT_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 74 ?? ?? ?? ?? 11 0c 11 07 58 11 09 59 93 61 11 0b 74 ?? ?? ?? ?? 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 01 00 0a 26 1f 10 13 0e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}