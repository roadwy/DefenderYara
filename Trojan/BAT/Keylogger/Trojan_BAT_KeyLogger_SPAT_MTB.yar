
rule Trojan_BAT_KeyLogger_SPAT_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SPAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 06 9a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 09 72 a1 00 00 70 16 28 ?? ?? ?? 0a 16 33 08 07 06 9a 6f ?? ?? ?? 0a 06 17 d6 0a 06 08 31 d3 } //3
		$a_01_1 = {62 00 65 00 6a 00 6e 00 36 00 36 00 36 00 53 00 74 00 75 00 62 00 } //1 bejn666Stub
		$a_01_2 = {40 44 6d 43 44 39 35 66 64 77 79 73 45 65 63 56 78 4a 62 52 41 40 } //1 @DmCD95fdwysEecVxJbRA@
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}