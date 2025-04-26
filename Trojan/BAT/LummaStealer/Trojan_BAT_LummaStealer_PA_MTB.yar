
rule Trojan_BAT_LummaStealer_PA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d2 61 d2 9c 08 09 8f ?? ?? ?? ?? 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}