
rule Trojan_BAT_Agent_MRS_MTB{
	meta:
		description = "Trojan:BAT/Agent.MRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {09 11 04 9a 0b 06 07 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 11 04 17 13 06 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 ?? ?? ?? ?? 20 ?? ?? ?? ?? 13 06 20 ?? ?? ?? ?? 58 00 58 13 04 11 04 09 8e 69 32 b8 02 03 06 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0c 08 14 04 6f ?? ?? ?? ?? 2a } //1
		$a_02_1 = {2d 11 14 fe ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}