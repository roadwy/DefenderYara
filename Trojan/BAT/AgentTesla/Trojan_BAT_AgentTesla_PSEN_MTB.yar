
rule Trojan_BAT_AgentTesla_PSEN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 b0 00 00 0a 0d 16 13 04 2b 32 09 08 17 8d 17 00 00 01 25 16 11 04 8c 63 00 00 01 a2 14 28 aa ?? ?? ?? 28 ae ?? ?? ?? 1f 10 28 b1 ?? ?? ?? 86 6f b2 ?? ?? ?? 00 11 04 } //5
		$a_01_1 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}