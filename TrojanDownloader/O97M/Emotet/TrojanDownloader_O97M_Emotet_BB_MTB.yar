
rule TrojanDownloader_O97M_Emotet_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 74 79 73 64 6a 6f 69 67 68 64 6c 66 6b 67 6e 78 6c 63 64 73 66 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 2c 20 22 77 67 6a 61 22 2c 20 22 22 29 } //1 = Replace(tysdjoighdlfkgnxlcdsf.TextBox1.Text, "wgja", "")
		$a_01_1 = {54 65 78 74 20 3d 20 22 63 77 67 6a 61 6d 64 20 2f 77 67 6a 61 63 20 73 77 67 6a 61 74 61 72 77 67 6a 61 74 2f 77 67 6a 61 42 } //1 Text = "cwgjamd /wgjac swgjatarwgjat/wgjaB
		$a_01_2 = {2e 54 61 67 20 3d 20 43 65 6c 6c 73 28 37 35 2c 20 31 29 20 2b 20 76 62 43 72 4c 66 20 2b 20 43 65 6c 6c 73 28 37 37 2c 20 31 29 } //1 .Tag = Cells(75, 1) + vbCrLf + Cells(77, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}