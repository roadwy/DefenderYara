
rule Trojan_BAT_Ader_PSID_MTB{
	meta:
		description = "Trojan:BAT/Ader.PSID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 05 00 00 70 28 ?? ?? ?? 0a 74 13 00 00 01 0a 06 6f ?? ?? ?? 0a 74 32 00 00 01 0b 73 ?? ?? ?? 0a 0c 00 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 80 03 00 00 04 00 de 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}