
rule Worm_Win32_Koobface_F{
	meta:
		description = "Worm:Win32/Koobface.F,SIGNATURE_TYPE_PEHSTR_EXT,38 00 37 00 0b 00 00 "
		
	strings :
		$a_00_0 = {6d 79 73 70 61 63 65 2e 63 6f 6d 2f } //1 myspace.com/
		$a_00_1 = {66 61 63 25 73 6f 6b 2e 63 6f 6d 2f } //1 fac%sok.com/
		$a_00_2 = {62 65 62 6f 2e 63 6f 6d 2f } //1 bebo.com/
		$a_00_3 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_00_4 = {55 73 65 25 73 69 6c 6c 25 73 6e 64 25 73 76 3a 31 2e 39 2e 30 2e 31 29 20 47 65 63 6b 6f 2f 32 30 30 38 30 37 30 32 30 38 20 46 69 72 65 66 6f 78 2f 33 2e 30 2e 31 } //1 Use%sill%snd%sv:1.9.0.1) Gecko/2008070208 Firefox/3.0.1
		$a_00_5 = {6d 75 63 68 6f 6d 61 6d 62 6f } //1 muchomambo
		$a_00_6 = {61 75 74 6f 74 75 72 6e 65 64 6f 66 66 } //10 autoturnedoff
		$a_00_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 25 73 2f 6d 61 69 6c 2f 4d 61 69 6c 43 6f 6d 70 6f 73 65 2e 6a 73 70 3f 54 6f 4d 65 6d 62 65 72 49 64 3d 25 73 } //10 http://www.%s/mail/MailCompose.jsp?ToMemberId=%s
		$a_00_8 = {6e 69 63 6b 3d 25 73 26 6c 6f 67 69 6e 3d 25 73 26 73 75 63 63 65 73 73 3d 25 64 26 66 72 69 65 6e 64 73 3d 25 64 26 63 61 70 74 63 68 61 3d 25 64 26 66 69 6e 69 73 68 3d 25 64 26 76 3d 25 73 26 70 3d 25 73 26 63 3d 25 64 } //10 nick=%s&login=%s&success=%d&friends=%d&captcha=%d&finish=%d&v=%s&p=%s&c=%d
		$a_01_9 = {6a 0a 33 d2 59 f7 f1 52 ff d6 } //10
		$a_01_10 = {99 6a 3c 59 f7 f9 52 ff d6 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10) >=55
 
}