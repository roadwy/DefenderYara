
rule Trojan_BAT_PhantomStealer_AIRB_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.AIRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 09 11 09 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 11 09 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 7e ?? ?? 00 04 2c 07 7e ?? ?? 00 04 2b 16 7e ?? ?? 00 04 fe ?? ?? ?? 00 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 13 0a 00 11 09 6f ?? ?? 00 0a 13 0b 02 11 0a 07 6f ?? ?? 00 0a 11 0b 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 de 0e } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}