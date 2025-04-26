
rule Trojan_BAT_AgentTesla_NAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 2e 00 00 0a 02 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 19 2d 03 26 de 06 0a 2b fb } //5
		$a_01_1 = {43 75 74 73 6f 67 67 77 67 } //1 Cutsoggwg
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NAT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f ?? ?? ?? 0a 0c 06 08 28 ?? ?? ?? 0a 07 59 28 ?? ?? ?? 0a 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 0a 11 04 17 58 13 04 11 04 09 6f ?? ?? ?? 0a 3f } //1
		$a_01_1 = {32 61 62 39 39 63 66 2d 38 65 33 35 2d 34 35 33 65 2d 38 38 64 36 2d 34 33 64 31 36 30 30 31 65 64 35 } //1 2ab99cf-8e35-453e-88d6-43d16001ed5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NAT_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 82 0f 00 70 20 ?? ?? ?? 21 38 ?? ?? ?? 00 72 ?? ?? ?? 70 20 ?? ?? ?? 54 38 ?? ?? ?? 00 72 ?? ?? ?? 70 61 38 ?? ?? ?? 00 72 ?? ?? ?? 70 20 ?? ?? ?? 75 38 ?? ?? ?? 00 72 ?? ?? ?? 70 40 ?? ?? ?? 00 38 ?? ?? ?? 00 72 ?? ?? ?? 70 } //5
		$a_01_1 = {4a 00 49 00 54 00 53 00 74 00 61 00 72 00 74 00 65 00 72 00 } //1 JITStarter
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}