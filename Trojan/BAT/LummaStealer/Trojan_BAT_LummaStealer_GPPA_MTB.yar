
rule Trojan_BAT_LummaStealer_GPPA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 47 11 00 11 06 91 61 d2 52 20 ?? 00 00 00 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}