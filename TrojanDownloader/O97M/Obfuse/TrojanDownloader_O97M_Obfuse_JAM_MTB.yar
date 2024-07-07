
rule TrojanDownloader_O97M_Obfuse_JAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 64 61 73 33 20 3d 20 22 74 22 20 2b 20 22 61 20 68 74 } //1 pdas3 = "t" + "a ht
		$a_01_1 = {6b 6f 34 64 20 3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f } //1 ko4d = "tp://%748237%728748@j.mp/
		$a_01_2 = {6f 6b 66 66 72 20 3d 20 22 64 68 6b 73 61 64 37 69 61 73 64 61 68 6d 6e 73 67 64 68 73 61 64 } //1 okffr = "dhksad7iasdahmnsgdhsad
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}