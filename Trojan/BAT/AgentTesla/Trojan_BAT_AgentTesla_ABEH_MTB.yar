
rule Trojan_BAT_AgentTesla_ABEH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 02 11 01 02 11 07 18 5a 18 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 38 90 01 03 ff dd 90 01 03 ff 11 03 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //00 00  GetResponseStream
	condition:
		any of ($a_*)
 
}