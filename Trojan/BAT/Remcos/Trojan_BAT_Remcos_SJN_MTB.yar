
rule Trojan_BAT_Remcos_SJN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 02 11 03 91 61 d2 6f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}