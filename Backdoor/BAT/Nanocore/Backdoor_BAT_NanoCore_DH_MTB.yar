
rule Backdoor_BAT_NanoCore_DH_MTB{
	meta:
		description = "Backdoor:BAT/NanoCore.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 28 ?? ?? ?? ?? 04 6f ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 0d 09 08 6f ?? ?? ?? ?? 00 09 18 6f ?? ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 13 04 11 04 05 16 05 8e 69 6f ?? ?? ?? ?? 13 05 09 6f ?? ?? ?? ?? 00 11 05 0a 2b 00 06 2a } //10
		$a_80_1 = {52 65 70 6c 61 63 65 } //Replace  1
		$a_80_2 = {53 70 6c 69 74 } //Split  1
		$a_80_3 = {54 6f 53 74 72 69 6e 67 } //ToString  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}