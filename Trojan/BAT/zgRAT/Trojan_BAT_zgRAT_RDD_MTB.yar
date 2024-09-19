
rule Trojan_BAT_ZgRAT_RDD_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 09 28 01 00 00 2b 28 02 00 00 2b 0d 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}