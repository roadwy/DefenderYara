
rule Trojan_BAT_AsyncRAT_RDP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 06 6f d8 00 00 0a 1f 20 06 6f d8 00 00 0a 8e 69 1f 20 59 6f d9 00 00 0a 0d } //00 00 
	condition:
		any of ($a_*)
 
}