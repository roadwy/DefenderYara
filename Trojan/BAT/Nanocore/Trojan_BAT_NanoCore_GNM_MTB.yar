
rule Trojan_BAT_NanoCore_GNM_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 07 08 08 6f ?? ?? ?? 0a 13 05 73 32 00 00 0a 13 06 11 06 11 05 17 73 33 00 00 0a 13 07 11 07 09 16 09 8e 69 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a de 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}