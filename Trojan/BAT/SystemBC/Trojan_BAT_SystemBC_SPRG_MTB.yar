
rule Trojan_BAT_SystemBC_SPRG_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.SPRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 13 30 11 0e 1e 63 d1 13 0e 11 18 11 09 91 13 20 11 18 11 09 11 20 11 28 61 11 1c 19 58 61 11 30 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}