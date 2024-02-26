
rule Trojan_BAT_AgentTesla_PSCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 16 73 07 90 01 03 73 08 90 01 03 13 03 38 16 90 01 03 fe 0c 00 00 45 02 90 01 03 6d 90 01 03 45 90 01 03 38 68 90 01 03 00 11 03 11 02 28 0a 00 00 06 38 90 01 03 00 dd 2c 90 01 03 11 03 6f 09 90 01 03 38 90 01 03 00 dc 20 01 90 01 03 7e 54 00 00 04 7b 17 00 00 04 39 b9 ff ff ff 26 20 01 90 01 03 38 ae ff ff ff 11 02 6f 0a 90 01 03 13 09 20 90 01 03 00 7e 54 00 00 04 7b 12 00 00 04 39 91 ff ff ff 26 20 90 01 03 00 38 86 ff ff ff dd 79 00 00 00 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_2 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}