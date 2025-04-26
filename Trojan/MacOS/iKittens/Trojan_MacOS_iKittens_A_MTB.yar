
rule Trojan_MacOS_iKittens_A_MTB{
	meta:
		description = "Trojan:MacOS/iKittens.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 4d 61 63 44 6f 77 6e 6c 6f 61 64 65 72 2f 4d 79 41 70 70 33 2f } //2 /MacDownloader/MyApp3/
		$a_00_1 = {2f 41 64 77 61 72 65 20 52 65 6d 6f 76 61 6c 20 54 6f 6f 6c 2e 62 75 69 6c 64 2f 44 65 62 75 67 2f 41 64 77 61 72 65 20 52 65 6d 6f 76 61 6c 20 54 6f 6f 6c 2e 62 75 69 6c 64 2f } //1 /Adware Removal Tool.build/Debug/Adware Removal Tool.build/
		$a_00_2 = {2f 65 74 63 2f 6b 63 62 61 63 6b 75 70 2e 63 66 67 20 2f 4c 69 62 72 61 72 79 2f 4b 65 79 63 68 61 69 6e 73 2f } //1 /etc/kcbackup.cfg /Library/Keychains/
		$a_00_3 = {2f 74 6d 70 2f 6d 61 73 74 65 72 69 6e 67 2d 76 69 6d 2e 70 64 66 } //1 /tmp/mastering-vim.pdf
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}