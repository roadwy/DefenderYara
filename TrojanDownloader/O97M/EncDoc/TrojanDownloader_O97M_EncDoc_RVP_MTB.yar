
rule TrojanDownloader_O97M_EncDoc_RVP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 38 30 29 2b 72 61 6e 67 65 28 22 63 36 22 29 2e 6e 6f 74 65 74 65 78 74 71 69 63 76 32 3d 22 22 2b 65 65 65 65 77 71 69 63 76 33 3d 71 69 63 76 31 26 71 69 63 76 32 6b 6c 73 61 64 28 29 2e 65 78 65 63 71 69 63 76 33 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 6b 6c 73 61 64 28 29 61 73 6f 62 6a 65 63 74 73 65 74 6b 6c 73 61 64 3d 67 65 74 6f 62 6a 65 63 74 28 72 61 6e 67 65 28 22 63 37 22 29 2e 6e 6f 74 65 74 65 78 74 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 =chr(80)+range("c6").notetextqicv2=""+eeeewqicv3=qicv1&qicv2klsad().execqicv3endfunctionfunctionklsad()asobjectsetklsad=getobject(range("c7").notetext)endfunction
		$a_01_1 = {3d 63 68 72 28 38 30 29 2b 72 61 6e 67 65 28 22 63 36 22 29 2e 6e 6f 74 65 74 65 78 74 75 75 7a 75 32 3d 22 22 2b 65 65 65 65 77 75 75 7a 75 33 3d 75 75 7a 75 31 26 75 75 7a 75 32 6b 6c 73 61 64 28 29 2e 65 78 65 63 75 75 7a 75 33 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 6b 6c 73 61 64 28 29 61 73 6f 62 6a 65 63 74 73 65 74 6b 6c 73 61 64 3d 67 65 74 6f 62 6a 65 63 74 28 72 61 6e 67 65 28 22 63 37 22 29 2e 6e 6f 74 65 74 65 78 74 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 =chr(80)+range("c6").notetextuuzu2=""+eeeewuuzu3=uuzu1&uuzu2klsad().execuuzu3endfunctionfunctionklsad()asobjectsetklsad=getobject(range("c7").notetext)endfunction
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}