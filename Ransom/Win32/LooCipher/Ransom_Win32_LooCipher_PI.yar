
rule Ransom_Win32_LooCipher_PI{
	meta:
		description = "Ransom:Win32/LooCipher.PI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 44 65 73 6b 74 6f 70 5c 40 4c 6f 6f 43 69 70 68 65 72 5f 77 61 6c 6c 70 61 70 65 72 2e 62 6d 70 } //1 \Desktop\@LooCipher_wallpaper.bmp
		$a_01_1 = {5c 44 65 73 6b 74 6f 70 5c 40 50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 2e 74 78 74 } //1 \Desktop\@Please_Read_Me.txt
		$a_01_2 = {5c 44 65 73 6b 74 6f 70 5c 63 32 30 35 36 2e 69 6e 69 } //1 \Desktop\c2056.ini
		$a_01_3 = {4c 00 6f 00 6f 00 43 00 69 00 70 00 68 00 65 00 72 00 } //1 LooCipher
		$a_01_4 = {5c 4c 6f 6f 43 69 70 68 65 72 2e 70 64 62 } //1 \LooCipher.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}