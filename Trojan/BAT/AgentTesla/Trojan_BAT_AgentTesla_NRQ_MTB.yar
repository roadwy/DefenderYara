
rule Trojan_BAT_AgentTesla_NRQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 88 00 00 5d 07 09 20 00 88 00 00 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 06 07 09 17 58 20 00 88 00 00 5d 91 28 90 01 03 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 06 9c 00 09 15 58 0d 09 90 00 } //1
		$a_01_1 = {33 63 39 34 2d 34 34 65 36 2d 61 64 66 33 2d } //1 3c94-44e6-adf3-
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}