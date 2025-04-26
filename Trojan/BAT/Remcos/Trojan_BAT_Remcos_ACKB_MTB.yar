
rule Trojan_BAT_Remcos_ACKB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ACKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 29 06 0c 16 0d 08 12 03 28 ?? ?? ?? 0a 06 03 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}