
rule Trojan_BAT_AsyncRAT_RDAG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {39 63 66 61 64 35 62 38 2d 35 35 39 63 2d 34 61 64 66 2d 38 64 39 66 2d 31 32 64 35 38 37 65 38 30 34 32 37 } //2 9cfad5b8-559c-4adf-8d9f-12d587e80427
		$a_01_1 = {43 68 72 6f 6d 65 20 49 6e 73 74 61 6c 6c 65 72 } //1 Chrome Installer
		$a_01_2 = {47 6f 6f 67 6c 65 20 4c 4c 43 } //1 Google LLC
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}