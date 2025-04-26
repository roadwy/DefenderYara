
rule Trojan_BAT_Amadey_PSUU_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PSUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 38 0b 00 00 00 26 20 05 00 00 00 38 9e ff ff ff 08 28 ?? ?? ?? 06 03 28 ?? 00 00 06 28 ?? 00 00 06 0b 20 02 00 00 00 17 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}