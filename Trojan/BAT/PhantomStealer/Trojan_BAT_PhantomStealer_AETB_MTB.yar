
rule Trojan_BAT_PhantomStealer_AETB_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.AETB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 01 28 ?? 00 00 0a 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 0f 01 28 ?? 00 00 0a 1e 63 20 ff 00 00 00 5f d2 9c 25 18 0f 01 28 ?? 00 00 0a 20 ff 00 00 00 5f d2 9c 2a } //5
		$a_03_1 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 00 06 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 7d ?? 00 00 04 06 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 7d ?? 00 00 04 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 0b 07 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 06 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}