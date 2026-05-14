
rule Trojan_Win32_Valleyrat_AMTB{
	meta:
		description = "Trojan:Win32/Valleyrat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 56 08 8b 45 14 8d 3c 11 8b 55 08 0f b6 04 02 99 bb c8 01 00 00 f7 fb ff 45 08 b8 cd cc cc cc 80 c2 36 30 17 f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Valleyrat_AMTB_2{
	meta:
		description = "Trojan:Win32/Valleyrat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {25 73 5c 44 6f 63 75 6d 65 6e 74 5c 5f 5c 5f 5c 5f 5c 5f 5c 5f } //%s\Document\_\_\_\_\_  1
		$a_80_1 = {5f 5c 5f 5c 5f 5c 5f 5c 64 6f 63 75 6d 65 6e 74 2e 62 61 74 } //_\_\_\_\document.bat  1
		$a_80_2 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 6d 73 69 6d 67 33 32 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 73 69 6d 67 33 32 2e 70 64 62 } //C:\Users\Administrator\Desktop\msimg32\x64\Release\msimg32.pdb  1
		$a_80_3 = {44 3a 5c 4d 61 6c 77 61 72 65 20 50 72 6f 6a 65 63 74 5c 6d 73 69 6d 67 33 32 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 73 69 6d 67 33 32 2e 70 64 62 } //D:\Malware Project\msimg32\x64\Release\msimg32.pdb  1
		$a_80_4 = {6d 73 69 6d 67 33 32 2e 64 6c 6c } //msimg32.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}