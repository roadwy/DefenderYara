
rule Trojan_BAT_Nanocore_AMAM_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AMAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 13 [0-0f] 61 [0-1e] 17 58 08 5d [0-32] 59 20 00 01 00 00 58 20 ff 00 00 00 5f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}