
rule Ransom_Win32_Filecoder_F_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.F!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 73 74 52 61 6e 73 6f 6d 65 2e 70 64 62 } //01 00  testRansome.pdb
		$a_01_1 = {44 61 74 61 2e 74 78 74 } //01 00  Data.txt
		$a_01_2 = {52 61 6e 73 6f 6d 65 77 61 72 65 49 6e 66 6f 42 61 63 6b 75 70 } //01 00  RansomewareInfoBackup
		$a_01_3 = {2e 74 78 74 2e 64 6f 63 2e 64 6f 63 78 2e 78 6c 73 2e 78 6c 73 78 2e 70 70 74 2e 70 70 74 78 2e 70 73 74 2e 6f 73 74 2e 6d 73 67 2e 65 6d 2e 76 73 64 2e 76 73 64 78 2e 63 73 76 2e 72 74 66 2e 31 32 33 2e 77 6b 73 2e 77 6b 31 2e 70 64 66 2e 64 77 67 2e 6f 6e 65 74 6f 63 32 2e 73 6e 74 2e 64 6f 63 62 2e 64 6f 63 6d 2e 64 6f 74 2e 64 6f 74 6d 2e 64 6f 74 78 2e 78 6c 73 6d 2e 78 6c 73 62 2e 78 6c 77 2e 78 6c 74 2e 78 6c 6d 2e } //00 00  .txt.doc.docx.xls.xlsx.ppt.pptx.pst.ost.msg.em.vsd.vsdx.csv.rtf.123.wks.wk1.pdf.dwg.onetoc2.snt.docb.docm.dot.dotm.dotx.xlsm.xlsb.xlw.xlt.xlm.
	condition:
		any of ($a_*)
 
}