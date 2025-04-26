
rule Trojan_BAT_Shelm_NSM_MTB{
	meta:
		description = "Trojan:BAT/Shelm.NSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 15 00 00 0a 0a 06 8e 2d 22 00 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 0a 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 14 2a 06 28 ?? ?? 00 2b 73 ?? ?? 00 0a } //5
		$a_01_1 = {43 00 68 00 61 00 74 00 67 00 70 00 74 00 2d 00 41 00 32 00 } //1 Chatgpt-A2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}