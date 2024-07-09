
rule Trojan_BAT_FileCoder_NC_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a 0a 12 00 fe ?? ?? ?? ?? 01 6f ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 2b 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}