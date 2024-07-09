
rule Trojan_BAT_AgentTesla_FAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {da 13 08 16 13 09 2b 1f 11 04 09 11 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 09 18 d6 13 09 11 09 11 08 31 db } //3
		$a_01_1 = {4c 00 55 00 47 00 5f 00 50 00 49 00 4d 00 49 00 5f 00 67 00 6f 00 6e 00 7a 00 61 00 6c 00 6f 00 5f 00 67 00 75 00 65 00 72 00 72 00 61 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 LUG_PIMI_gonzalo_guerra.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}