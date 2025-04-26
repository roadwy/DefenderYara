
rule Trojan_BAT_Androm_SPJR_MTB{
	meta:
		description = "Trojan:BAT/Androm.SPJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 16 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 13 06 09 11 06 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a 32 d4 09 6f ?? ?? ?? 0a 13 07 dd 0d 00 00 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}