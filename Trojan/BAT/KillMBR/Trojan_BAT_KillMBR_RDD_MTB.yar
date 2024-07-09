
rule Trojan_BAT_KillMBR_RDD_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 08 16 08 8e 69 6f ?? ?? ?? ?? 11 07 17 58 13 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}