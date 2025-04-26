
rule Trojan_BAT_CryptBot_BL_MTB{
	meta:
		description = "Trojan:BAT/CryptBot.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 17 73 ?? ?? 00 0a 0d 2b 11 2b 12 16 2b 12 8e 69 2b 11 2b 16 2b 17 2b 1c de 48 09 2b ec 03 2b eb 03 2b eb 6f ?? 00 00 0a 2b e8 08 2b e7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}