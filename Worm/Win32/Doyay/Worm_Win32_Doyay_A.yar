
rule Worm_Win32_Doyay_A{
	meta:
		description = "Worm:Win32/Doyay.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 2e 3a 3a 20 49 50 2d 57 6f 52 4d 20 57 75 5a 20 48 65 52 45 20 3a 3a 2e 2e } //1 ..:: IP-WoRM WuZ HeRE ::..
		$a_01_1 = {4d 61 61 66 2e 20 41 6b 73 65 73 20 61 6e 64 61 20 75 6e 74 75 6b 20 6d 65 6d 62 75 6b 61 20 47 61 6d 62 61 72 2f 46 69 6c 6d 20 50 6f 72 6e 6f 20 74 65 6c 61 68 20 6b 61 6d 69 20 62 61 74 61 73 69 2e 20 4b 6c 69 6b 20 74 6f 6d 62 6f 6c 20 59 45 53 20 61 70 61 62 69 6c 61 20 61 6e 64 61 20 73 65 74 75 6a 75 20 64 65 6e 67 61 6e 20 70 65 6d 62 61 74 61 73 61 6e 20 69 6e 69 2c 20 61 74 61 75 20 6b 6c 69 6b 20 4e 4f 20 61 70 61 62 69 6c 61 20 61 6e 64 61 20 } //1 Maaf. Akses anda untuk membuka Gambar/Film Porno telah kami batasi. Klik tombol YES apabila anda setuju dengan pembatasan ini, atau klik NO apabila anda 
		$a_00_2 = {5c 00 59 00 61 00 44 00 6f 00 59 00 20 00 53 00 6f 00 46 00 74 00 57 00 61 00 52 00 65 00 20 00 44 00 65 00 56 00 65 00 4c 00 6f 00 50 00 6d 00 45 00 6e 00 54 00 5c 00 46 00 4f 00 52 00 20 00 50 00 45 00 52 00 42 00 41 00 4e 00 41 00 53 00 5c 00 46 00 6f 00 72 00 53 00 6b 00 72 00 69 00 70 00 73 00 69 00 5c 00 56 00 69 00 72 00 69 00 5c 00 46 00 6f 00 72 00 53 00 6b 00 72 00 69 00 70 00 73 00 69 00 2e 00 76 00 62 00 70 00 } //1 \YaDoY SoFtWaRe DeVeLoPmEnT\FOR PERBANAS\ForSkripsi\Viri\ForSkripsi.vbp
		$a_02_3 = {6b 00 31 00 63 00 6b 00 74 00 68 00 33 00 77 00 30 00 72 00 6d 00 [0-10] 6b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}