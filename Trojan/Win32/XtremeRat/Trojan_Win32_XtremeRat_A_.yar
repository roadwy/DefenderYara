
rule Trojan_Win32_XtremeRat_A_{
	meta:
		description = "Trojan:Win32/XtremeRat.A!!XtremeRat.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {58 74 72 65 6d 65 4b 65 } //1 XtremeKe
		$a_81_1 = {66 74 70 2e 66 74 70 73 65 72 76 65 72 2e 63 6f 6d } //1 ftp.ftpserver.com
		$a_81_2 = {58 74 72 65 6d 65 20 52 41 54 } //1 Xtreme RAT
		$a_81_3 = {25 4e 4f 49 4e 4a 45 43 54 25 } //1 %NOINJECT%
		$a_81_4 = {72 65 73 74 61 72 74 } //1 restart
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}