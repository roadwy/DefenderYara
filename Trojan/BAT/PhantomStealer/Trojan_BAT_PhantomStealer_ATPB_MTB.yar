
rule Trojan_BAT_PhantomStealer_ATPB_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.ATPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0f 06 7b ?? 00 00 04 11 0a 11 0e 6f ?? 00 00 0a 7d ?? 00 00 04 11 06 17 58 13 06 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6c 23 89 41 60 e5 d0 22 d3 3f 5a 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6c 23 62 10 58 39 b4 c8 e2 3f 5a 58 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6c 23 c9 76 be 9f 1a 2f bd 3f 5a 58 13 10 11 10 23 00 00 00 00 00 00 60 40 fe 02 13 11 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 13 13 11 13 2c 18 06 7b ?? 00 00 04 11 0f 7c ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}