
rule Trojan_BAT_Lazy_GNC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {6b 6c 65 6e 65 63 65 6b 74 69 72 2e 20 59 65 64 65 6b 6c 65 6d 65 20 73 74 72 61 74 65 6a 69 6e 69 7a 65 20 67 } //klenecektir. Yedekleme stratejinize g  1
		$a_80_1 = {48 61 6c 65 6e 20 64 65 76 61 6d 20 65 64 65 6e 20 62 69 72 20 79 65 64 65 6b 6c 65 6d 65 20 69 } //Halen devam eden bir yedekleme i  1
		$a_80_2 = {41 72 6b 61 70 6c 61 6e 20 75 79 67 75 6c 61 6d 61 73 } //Arkaplan uygulamas  1
		$a_80_3 = {62 61 63 6b 75 70 73 6f 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 } //backupso.com/download  1
		$a_80_4 = {48 65 72 68 61 6e 67 69 20 62 69 72 20 46 54 50 2f 53 46 54 50 } //Herhangi bir FTP/SFTP  1
		$a_80_5 = {7a 61 6d 61 6e 6c 69 2e 74 78 74 } //zamanli.txt  1
		$a_80_6 = {42 61 63 6b 75 70 73 6f 2e 65 78 65 } //Backupso.exe  1
		$a_80_7 = {6b 61 70 61 74 73 69 6e 6d 69 } //kapatsinmi  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}