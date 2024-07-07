
rule Trojan_BAT_Remcos_AHLN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 5d 91 02 08 91 61 d2 6f 90 01 03 0a 08 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}