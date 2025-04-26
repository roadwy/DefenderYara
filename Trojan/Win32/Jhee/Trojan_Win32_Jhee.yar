
rule Trojan_Win32_Jhee{
	meta:
		description = "Trojan:Win32/Jhee,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {f3 a5 8b c8 33 c0 83 e1 03 8d ?? ?? ?? f3 a4 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 50 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 68 80 00 00 00 } //1
		$a_00_1 = {75 70 2e 64 6c 6c 2e 7a 67 78 } //1 up.dll.zgx
		$a_00_2 = {73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 } //1 sysoption.ini
		$a_00_3 = {6d 69 6e 69 44 6c 6c 2e 64 6c 6c 2e 7a 67 78 } //1 miniDll.dll.zgx
		$a_00_4 = {5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 \Explorer\Run
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}