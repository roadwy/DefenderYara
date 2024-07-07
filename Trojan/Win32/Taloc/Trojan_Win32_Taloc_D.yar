
rule Trojan_Win32_Taloc_D{
	meta:
		description = "Trojan:Win32/Taloc.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4e 72 69 6c 5c 73 79 65 74 6f 6d 2e 65 78 65 } //1 Nril\syetom.exe
		$a_00_1 = {2f 63 67 69 5f 70 65 72 73 6f 6e 61 6c 5f 63 61 72 64 3f 75 69 6e 3d } //1 /cgi_personal_card?uin=
		$a_00_2 = {6e 69 63 6b 6e 61 6d 65 22 3a 22 } //1 nickname":"
		$a_00_3 = {73 00 79 00 65 00 74 00 6f 00 6d 00 } //1 syetom
		$a_00_4 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4e 00 72 00 69 00 6c 00 } //1 \Program Files\Nril
		$a_02_5 = {52 75 6e 5c 90 02 04 77 69 6e 64 69 72 90 02 04 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}