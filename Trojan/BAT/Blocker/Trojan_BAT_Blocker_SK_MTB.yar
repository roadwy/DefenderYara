
rule Trojan_BAT_Blocker_SK_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 58 0b 07 09 6f ?? ?? ?? 0a 32 dd } //2
		$a_81_1 = {46 72 61 63 74 69 6f 6e 73 2e 45 78 63 65 70 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Fractions.Exceptions.resources
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}