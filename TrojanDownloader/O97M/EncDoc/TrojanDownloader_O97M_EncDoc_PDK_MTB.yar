
rule TrojanDownloader_O97M_EncDoc_PDK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 6f 70 65 6e 28 29 6f 6c 65 70 72 61 3d 22 72 75 6e 24 33 32 23 68 65 7e 2e 24 2c 23 68 65 6c 6c 65 78 65 63 2a 75 6e 24 22 22 40 22 22 22 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 38 34 71 32 33 63 7a 75 39 66 33 65 69 64 38 2f 31 30 2e 68 74 6d 2f 66 69 6c 65 22 22 22 6f 6c 65 70 72 61 3d 76 62 61 2e } //1 _open()olepra="run$32#he~.$,#hellexec*un$""@""""https://www.mediafire.com/file/84q23czu9f3eid8/10.htm/file"""olepra=vba.
		$a_01_1 = {3d 76 62 61 2e 72 65 70 6c 61 63 65 28 6f 6c 65 70 72 61 2c 22 2a 22 2c 22 5f 72 22 29 } //1 =vba.replace(olepra,"*","_r")
		$a_01_2 = {3d 65 70 69 76 61 6c 5f 2e 5f 5f 65 78 65 63 21 28 6f 6c 65 70 72 61 29 64 65 62 75 67 2e 70 72 69 6e 74 6f 75 74 70 75 74 3d 72 65 62 72 61 69 6e 2e 73 74 64 6f 75 74 2e 72 65 61 64 61 6c 6c 28 29 65 6e 64 73 75 62 } //1 =epival_.__exec!(olepra)debug.printoutput=rebrain.stdout.readall()endsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}