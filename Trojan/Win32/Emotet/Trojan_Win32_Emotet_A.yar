
rule Trojan_Win32_Emotet_A{
	meta:
		description = "Trojan:Win32/Emotet.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 cb 6b 28 af f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 13 8b ce 2b c8 } //1
		$a_80_1 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 25 63 25 63 25 63 25 53 2e 65 78 65 } //%s\Microsoft\%c%c%c%S.exe  1
		$a_02_2 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 90 02 0a 2e 65 78 65 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 90 00 } //1
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN  1
		$a_00_4 = {43 00 3a 00 5c 00 21 00 64 00 62 00 67 00 5c 00 73 00 70 00 65 00 2e 00 6c 00 6f 00 67 00 } //1 C:\!dbg\spe.log
		$a_03_5 = {72 65 67 3a 5c 75 6e 6b 6e 6f 77 6e 90 02 0a 66 73 3a 5c 75 6e 6b 6e 6f 77 6e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}