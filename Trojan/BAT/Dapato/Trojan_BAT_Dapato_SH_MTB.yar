
rule Trojan_BAT_Dapato_SH_MTB{
	meta:
		description = "Trojan:BAT/Dapato.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 1c 00 00 0a 7e 0d 00 00 04 07 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 28 ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 7e 10 00 00 04 2c 08 02 11 04 28 1d 00 00 06 11 04 13 05 de 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}