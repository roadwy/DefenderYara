
rule Ransom_Win32_Daxxed_A_{
	meta:
		description = "Ransom:Win32/Daxxed.A!!Daxxed.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 4d 0c c1 e9 02 8b 15 19 30 40 00 8b 75 08 8b fe ad 0f c8 33 c2 c1 c8 03 ab c1 c2 05 } //2
		$a_00_1 = {4c 65 67 61 6c 4e 6f 74 69 63 65 43 61 70 74 69 6f 6e } //1 LegalNoticeCaption
		$a_00_2 = {4c 65 67 61 6c 4e 6f 74 69 63 65 54 65 78 74 } //1 LegalNoticeText
		$a_00_3 = {59 6f 75 72 20 73 65 72 76 65 72 20 68 61 63 6b 65 64 } //1 Your server hacked
		$a_00_4 = {2e 64 62 66 2e 70 6c 6c 2e 6e 74 78 2e 6f 76 6c 2e 70 72 6e 2e 63 68 6d 2e 62 6d 70 2e 69 6e 69 } //1 .dbf.pll.ntx.ovl.prn.chm.bmp.ini
		$a_01_5 = {52 65 61 64 4d 65 2e 54 78 54 } //1 ReadMe.TxT
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}