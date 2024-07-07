
rule Trojan_Win32_Phaetp_E_dha{
	meta:
		description = "Trojan:Win32/Phaetp.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 49 6e 73 64 6c 6c 2e 70 64 62 } //2 \Insdll.pdb
		$a_00_1 = {5c 65 78 70 5c 4e 65 77 50 6f 70 5c } //2 \exp\NewPop\
		$a_01_2 = {68 74 74 70 73 68 65 6c 70 65 72 2e 64 6c 6c } //2 httpshelper.dll
		$a_01_3 = {48 74 74 70 73 49 6e 69 74 00 } //1 瑈灴䥳楮t
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}