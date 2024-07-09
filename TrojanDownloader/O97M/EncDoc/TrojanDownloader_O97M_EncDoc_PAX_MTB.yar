
rule TrojanDownloader_O97M_EncDoc_PAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 76 62 75 77 65 75 77 22 } //1 vb_name="vbuweuw"
		$a_01_1 = {76 62 5f 6e 61 6d 65 3d 22 76 6e 62 69 65 75 62 74 61 6f 69 34 75 64 69 67 22 } //1 vb_name="vnbieubtaoi4udig"
		$a_01_2 = {2e 74 65 78 74 3d 22 63 77 67 6a 61 6d 64 2f 77 67 6a 61 63 73 77 67 6a 61 74 61 72 77 67 6a 61 74 2f 77 67 6a 61 62 22 } //1 .text="cwgjamd/wgjacswgjatarwgjat/wgjab"
		$a_01_3 = {2e 74 65 78 74 62 6f 78 31 2e 74 65 78 74 3d 22 63 77 67 6a 61 6d 64 2f 77 67 6a 61 63 73 77 67 6a 61 74 61 72 77 67 6a 61 74 2f 77 67 6a 61 62 22 } //1 .textbox1.text="cwgjamd/wgjacswgjatarwgjat/wgjab"
		$a_03_4 = {2e 74 65 78 74 3d 72 65 70 6c 61 63 65 28 [0-7f] 2e 74 65 78 74 62 6f 78 34 2e 74 65 78 74 2c 22 77 67 6a 61 22 2c 22 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}