
rule Trojan_BAT_PhantomStealer_AUQB_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.AUQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 09 11 0a 6f ?? 00 00 0a 13 0c 12 0c 28 ?? 00 00 0a 13 0d 12 0c 28 ?? 00 00 0a 13 0e 12 0c 28 ?? 00 00 0a 13 0f 11 0d 28 ?? 00 00 06 13 10 11 0e 28 ?? 00 00 06 13 11 11 0f 28 ?? 00 00 06 13 12 11 10 11 11 5f 11 12 5f } //5
		$a_01_1 = {11 0d 1b 62 11 0d 19 63 60 d2 13 0d 11 0d 1b 63 11 0d 19 62 60 d2 13 0d 11 0e 20 f3 00 00 00 58 20 ff 00 00 00 5f d2 13 0e 11 0e 20 f3 00 00 00 59 20 ff 00 00 00 5f d2 13 0e 11 0f 20 c8 00 00 00 61 d2 13 0f 11 0f 20 c8 00 00 00 61 d2 13 0f 11 07 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}