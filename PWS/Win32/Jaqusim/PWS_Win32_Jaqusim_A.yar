
rule PWS_Win32_Jaqusim_A{
	meta:
		description = "PWS:Win32/Jaqusim.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0d 00 00 "
		
	strings :
		$a_01_0 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c 72 66 } //2 boundary="=_NextPart_2relrf
		$a_01_1 = {2d 2d 37 63 66 38 37 32 32 34 64 32 30 32 30 61 } //1 --7cf87224d2020a
		$a_01_2 = {48 6f 73 74 3a 20 6c 6f 67 69 6e 2e 70 61 73 73 70 6f 72 74 2e 63 6f 6d } //1 Host: login.passport.com
		$a_01_3 = {54 42 53 4d 53 4e 43 68 61 74 53 65 73 73 69 6f 6e 55 } //2 TBSMSNChatSessionU
		$a_01_4 = {2c 73 69 67 6e 2d 69 6e 3d } //1 ,sign-in=
		$a_01_5 = {31 33 34 32 31 37 37 32 38 30 } //1 1342177280
		$a_01_6 = {30 78 30 34 31 33 20 77 69 6e 6e 74 20 35 2e 31 20 69 33 38 36 20 4d 53 4e 4d 53 47 52 } //2 0x0413 winnt 5.1 i386 MSNMSGR
		$a_00_7 = {40 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 2e 00 6a 00 70 00 } //1 @hotmail.co.jp
		$a_01_8 = {6d 65 73 61 6a 63 65 6b 2e 61 73 70 3f } //1 mesajcek.asp?
		$a_01_9 = {4b 41 54 45 47 4f 52 49 3d 57 45 42 4d 41 49 4c } //1 KATEGORI=WEBMAIL
		$a_01_10 = {6d 61 69 6c 63 65 6b 2e 61 73 70 } //1 mailcek.asp
		$a_01_11 = {6f 72 74 61 6d 61 61 79 61 72 63 65 6b } //1 ortamaayarcek
		$a_01_12 = {6d 73 6e 67 69 72 69 73 4c 6f 67 69 6e 53 75 63 63 65 73 73 } //1 msngirisLoginSuccess
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=11
 
}