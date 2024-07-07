
rule Ransom_Win32_CryptoLemPiz_A{
	meta:
		description = "Ransom:Win32/CryptoLemPiz.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {3b 62 6f 6f 74 2e 69 6e 69 3b 4e 54 44 45 54 45 43 54 2e 43 4f 4d 3b 42 6f 6f 74 66 6f 6e 74 2e 62 69 6e 3b 6e 74 6c 64 72 3b 62 6f 6f 74 6d 67 72 3b 42 4f 4f 54 4e 58 54 3b 42 4f 4f 54 53 45 43 54 2e 42 41 4b 3b 4e 54 55 53 45 52 2e 44 41 54 3b 50 44 4f 58 55 53 52 53 2e 4e 45 54 3b } //2 ;boot.ini;NTDETECT.COM;Bootfont.bin;ntldr;bootmgr;BOOTNXT;BOOTSECT.BAK;NTUSER.DAT;PDOXUSRS.NET;
		$a_01_1 = {20 49 4e 46 4f } //1  INFO
		$a_00_2 = {67 00 6f 00 74 00 6f 00 20 00 74 00 72 00 79 00 00 00 } //1
		$a_00_3 = {00 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 00 00 } //1
		$a_00_4 = {00 00 74 00 65 00 6d 00 70 00 30 00 30 00 30 00 30 00 30 00 30 00 2e 00 74 00 78 00 74 00 00 00 } //1
		$a_00_5 = {43 72 79 70 74 4f 4e 5c 6c 6f 63 6b 5c 78 41 45 53 2e 70 61 73 00 } //2
		$a_00_6 = {8b c3 e8 98 ff ff ff 88 04 2e 45 8a 04 2e 84 c0 75 ec 8b c6 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2) >=5
 
}