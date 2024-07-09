
rule TrojanSpy_Win32_Bancos_ZY{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZY,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {7c 2e 43 33 ff 8d 45 f8 50 8b 45 fc e8 ?? ?? ?? ff 8b d0 2b d7 b9 01 00 00 00 8b 45 fc e8 ?? ?? ?? ff 8b 55 f8 8b c6 e8 ?? ?? ?? ff 47 4b 75 d5 } //5
		$a_00_1 = {65 64 74 73 65 6e 68 61 } //1 edtsenha
		$a_00_2 = {70 6e 6c 62 62 70 61 73 73 } //1 pnlbbpass
		$a_00_3 = {73 65 6e 64 6d 61 69 6c } //1 sendmail
		$a_00_4 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2d 66 20 2d 69 6d } //1 taskkill.exe -f -im
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=9
 
}