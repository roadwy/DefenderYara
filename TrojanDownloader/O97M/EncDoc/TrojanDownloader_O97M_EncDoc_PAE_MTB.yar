
rule TrojanDownloader_O97M_EncDoc_PAE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 66 65 65 64 62 61 63 6b 22 } //1 vb_name="feedback"
		$a_01_1 = {6c 62 6f 75 6e 64 28 6c 69 6e 65 73 2c 31 29 74 6f 75 62 6f 75 6e 64 28 6c 69 6e 65 73 2c 31 29 66 69 65 6c 64 73 3d 73 70 6c 69 74 28 6c 69 6e 65 73 28 69 29 2c 22 7c 22 2c 33 29 69 66 75 62 6f 75 6e 64 28 66 69 65 6c 64 73 29 3d 30 } //1 lbound(lines,1)toubound(lines,1)fields=split(lines(i),"|",3)ifubound(fields)=0
		$a_01_2 = {70 72 6f 63 65 73 73 28 6f 62 6a 2e 72 65 73 70 6f 6e 73 65 74 65 78 74 29 65 6e 64 69 66 65 6e 64 73 75 62 } //1 process(obj.responsetext)endifendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}