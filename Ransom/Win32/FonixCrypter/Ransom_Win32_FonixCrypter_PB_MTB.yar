
rule Ransom_Win32_FonixCrypter_PB_MTB{
	meta:
		description = "Ransom:Win32/FonixCrypter.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce  1
		$a_80_1 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 2e 68 74 61 } //How To Decrypt Files.hta  4
		$a_80_2 = {48 65 6c 70 2e 74 78 74 } //Help.txt  4
		$a_80_3 = {73 63 68 74 61 73 6b 73 20 2f 43 52 45 41 54 45 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 4e } //schtasks /CREATE /SC ONLOGON /TN  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*1) >=10
 
}