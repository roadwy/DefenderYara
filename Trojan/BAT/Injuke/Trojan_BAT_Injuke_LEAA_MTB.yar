
rule Trojan_BAT_Injuke_LEAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.LEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 2b 42 2b 25 2b 41 7b ?? 00 00 04 7b ?? 00 00 04 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 07 6f ?? 00 00 0a 32 d2 } //4
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}