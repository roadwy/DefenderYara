
rule Trojan_Win32_BlackPunisher_YAA_MTB{
	meta:
		description = "Trojan:Win32/BlackPunisher.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 6c 61 63 6b 50 75 6e 69 73 68 65 72 45 78 63 6c 75 } //1 BlackPunisherExclu
		$a_01_1 = {73 65 6c 66 5f 64 65 6c 65 74 69 6e 67 5f 73 63 72 69 70 74 2e 76 62 73 } //1 self_deleting_script.vbs
		$a_01_2 = {73 79 6e 63 5c 72 65 65 6e 74 72 61 6e 74 5f 6c 6f 63 6b 2e 72 73 } //1 sync\reentrant_lock.rs
		$a_01_3 = {2e 64 6f 63 2e 64 6f 63 78 2e 78 6c 73 2e 78 6c 73 78 2e 70 70 74 2e 70 70 74 78 2e 70 73 74 2e 6f 73 74 2e 6d 73 67 2e 65 6d 6c 2e 76 73 64 2e 76 73 64 78 2e 74 78 74 2e 63 73 76 2e 72 74 66 2e 31 32 33 2e 77 6b 73 2e 77 6b 31 2e 70 64 66 2e } //1 .doc.docx.xls.xlsx.ppt.pptx.pst.ost.msg.eml.vsd.vsdx.txt.csv.rtf.123.wks.wk1.pdf.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}