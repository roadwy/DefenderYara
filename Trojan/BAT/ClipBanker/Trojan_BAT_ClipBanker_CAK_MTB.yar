
rule Trojan_BAT_ClipBanker_CAK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 17 00 02 07 95 28 ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d df } //2
		$a_01_1 = {24 65 36 62 34 38 35 30 34 2d 37 32 35 36 2d 34 36 31 64 2d 61 62 39 34 2d 65 39 38 34 62 35 30 31 61 64 38 33 } //2 $e6b48504-7256-461d-ab94-e984b501ad83
		$a_01_2 = {41 00 64 00 6f 00 62 00 65 00 43 00 6c 00 69 00 70 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 AdobeClipp.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}