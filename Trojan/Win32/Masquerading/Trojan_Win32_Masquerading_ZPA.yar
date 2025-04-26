
rule Trojan_Win32_Masquerading_ZPA{
	meta:
		description = "Trojan:Win32/Masquerading.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_00_0 = {2e 00 64 00 6f 00 63 00 78 00 2e 00 65 00 78 00 65 00 } //1 .docx.exe
		$a_00_1 = {2e 00 70 00 64 00 66 00 2e 00 65 00 78 00 65 00 } //1 .pdf.exe
		$a_00_2 = {2e 00 70 00 73 00 31 00 2e 00 65 00 78 00 65 00 } //1 .ps1.exe
		$a_00_3 = {2e 00 78 00 6c 00 73 00 2e 00 76 00 62 00 73 00 } //1 .xls.vbs
		$a_00_4 = {2e 00 78 00 6c 00 73 00 78 00 2e 00 76 00 62 00 73 00 } //1 .xlsx.vbs
		$a_00_5 = {2e 00 70 00 6e 00 67 00 2e 00 76 00 62 00 73 00 } //1 .png.vbs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=1
 
}