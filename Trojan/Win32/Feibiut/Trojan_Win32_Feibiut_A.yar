
rule Trojan_Win32_Feibiut_A{
	meta:
		description = "Trojan:Win32/Feibiut.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 50 4f 4c 44 00 } //1 偕䱏D
		$a_01_1 = {25 73 5c 7e 25 64 2e 65 78 65 } //1 %s\~%d.exe
		$a_01_2 = {64 47 46 7a 61 79 35 6b 62 6e 4d 74 63 33 6c 75 4c 6d 4e 76 62 51 3d 3d } //1 dGFzay5kbnMtc3luLmNvbQ==
		$a_01_3 = {2f 63 6f 6e 66 69 67 3f 74 3d 25 49 36 34 64 26 76 3d 25 64 } //1 /config?t=%I64d&v=%d
		$a_01_4 = {5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 54 72 69 65 64 69 74 } //1 \Microsoft Shared\Triedit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}