
rule Trojan_Win32_Alpasog_A{
	meta:
		description = "Trojan:Win32/Alpasog.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {66 69 76 65 65 76 69 66 00 } //1
		$a_01_1 = {73 65 72 76 69 63 65 5f 64 6c 6c 2e 64 6c 6c } //1 service_dll.dll
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6e 6f 74 65 2e 69 6e 69 } //1 c:\windows\note.ini
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 75 70 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 74 69 74 6c 65 2e 67 69 66 22 } //1 Content-Disposition: form-data; name="upfile"; filename="title.gif"
		$a_01_4 = {44 63 7a 55 39 58 6d 5a 77 6a 49 74 64 73 4a 72 70 6c 61 70 32 51 3d 3d } //1 DczU9XmZwjItdsJrplap2Q==
		$a_01_5 = {43 4e 44 6e 6b 7a 51 62 47 4a 55 68 68 59 39 37 32 31 69 32 63 67 3d 3d } //1 CNDnkzQbGJUhhY9721i2cg==
		$a_03_6 = {8b d1 c1 fa ?? 08 14 30 03 f7 c0 e1 ?? 88 0c 30 } //1
		$a_03_7 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=6
 
}