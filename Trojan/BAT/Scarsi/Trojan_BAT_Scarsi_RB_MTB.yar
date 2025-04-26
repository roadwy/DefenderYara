
rule Trojan_BAT_Scarsi_RB_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}