
rule Trojan_BAT_AgentTesla_SOP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 07 11 0d d4 11 0e 6e 11 11 20 ff 00 00 00 5f 6a 61 d2 9c 00 11 0d 17 6a 58 13 0d 11 0d 11 07 8e 69 17 59 6a fe 02 16 fe 01 13 12 } //1
		$a_81_1 = {45 53 48 30 47 38 41 37 33 53 42 41 47 37 38 47 4e 39 5a 5a 48 34 } //1 ESH0G8A73SBAG78GN9ZZH4
		$a_81_2 = {44 65 76 69 63 65 73 5f 43 75 73 74 6f 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Devices_Custom.Properties.Resources
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}