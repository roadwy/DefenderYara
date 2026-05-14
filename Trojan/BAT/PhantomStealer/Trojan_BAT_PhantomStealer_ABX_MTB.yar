
rule Trojan_BAT_PhantomStealer_ABX_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.ABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 00 06 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? 7e 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 7d ?? 00 00 04 06 06 fe ?? 74 00 00 06 73 ?? 00 00 0a 7d ?? 00 00 04 06 } //5
		$a_03_1 = {25 16 0f 01 28 ?? 01 00 0a 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 0f 01 28 ?? 01 00 0a 1e 63 20 ff 00 00 00 5f d2 9c 25 18 0f 01 28 ?? 01 00 0a 20 ff 00 00 00 5f d2 9c 2a } //4
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4+(#a_80_2  & 1)*1) >=10
 
}