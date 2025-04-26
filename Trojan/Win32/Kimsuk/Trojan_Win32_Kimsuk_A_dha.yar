
rule Trojan_Win32_Kimsuk_A_dha{
	meta:
		description = "Trojan:Win32/Kimsuk.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 85 db f3 a4 7e 0e 8a 0c 10 80 f1 99 88 0c 10 40 3b c3 7c f2 } //1
		$a_01_1 = {8a 4c 30 ff 30 0c 30 48 85 c0 7f f4 80 36 ac c6 04 37 00 5f } //1
		$a_01_2 = {33 c0 85 f6 7e 09 80 34 38 99 40 3b c6 7c f7 8b c7 } //1
		$a_01_3 = {26 72 65 61 64 72 65 73 70 6f 6e 73 65 3d 30 26 73 61 76 65 61 74 74 61 63 68 6d 65 6e 74 73 3d 31 26 73 61 76 65 69 6e 73 65 6e 74 3d 31 26 6c 69 6e 6b 61 74 74 61 63 68 6d 65 6e 74 73 3d 30 26 72 65 63 61 70 74 63 68 61 5f 72 65 73 70 6f 6e 73 65 5f 66 69 65 6c 64 3d 26 } //1 &readresponse=0&saveattachments=1&saveinsent=1&linkattachments=0&recaptcha_response_field=&
		$a_03_4 = {68 a9 04 bc 6a e8 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 51 68 cf 72 18 6c e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 52 68 f2 e2 b7 1b e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 68 99 9f 81 de e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 51 68 56 07 cc e5 e8 } //1
		$a_01_5 = {8d 49 00 0f be 14 39 03 f2 8b c6 c1 e8 0e c1 e6 12 03 f0 8b c1 47 8d 58 01 8a 10 40 84 d2 75 f9 2b c3 3b f8 72 dd 3b 74 24 24 74 0f 8b 44 24 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}