
rule Worm_Win32_Basowdu_A{
	meta:
		description = "Worm:Win32/Basowdu.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {40 6d 61 69 6c 2e 72 75 23 73 6d 74 70 2e 6d 61 69 6c 2e 72 75 23 } //2 @mail.ru#smtp.mail.ru#
		$a_01_1 = {73 73 74 6d 5c 63 64 70 61 74 68 2e 74 78 74 } //2 sstm\cdpath.txt
		$a_01_2 = {6d 6f 75 73 65 75 70 } //1 mouseup
		$a_01_3 = {67 65 74 69 6d 67 } //1 getimg
		$a_01_4 = {62 6c 6f 63 6b 64 61 74 61 } //1 blockdata
		$a_01_5 = {67 65 74 6c 6f 67 } //1 getlog
		$a_01_6 = {73 73 74 6d 65 6d 61 69 6c } //1 sstmemail
		$a_00_7 = {64 65 63 6f 64 20 43 3a 5c } //1 decod C:\
		$a_01_8 = {63 6f 64 65 72 75 70 64 } //1 coderupd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}