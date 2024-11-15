
rule Trojan_BAT_BazaarLoader_OSH_MTB{
	meta:
		description = "Trojan:BAT/BazaarLoader.OSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 4d 48 75 62 2e 64 6c 6c } //1 SMHub.dll
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_2 = {46 30 30 42 39 35 42 41 2d 39 35 31 42 2d 34 41 45 35 2d 42 34 32 44 2d 45 31 36 34 31 43 35 31 36 39 42 38 } //1 F00B95BA-951B-4AE5-B42D-E1641C5169B8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}