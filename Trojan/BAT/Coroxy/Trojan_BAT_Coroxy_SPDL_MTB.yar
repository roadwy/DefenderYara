
rule Trojan_BAT_Coroxy_SPDL_MTB{
	meta:
		description = "Trojan:BAT/Coroxy.SPDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 21 11 22 61 19 11 1f 58 61 11 34 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}