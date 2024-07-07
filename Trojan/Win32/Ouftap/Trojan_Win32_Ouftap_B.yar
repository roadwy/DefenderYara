
rule Trojan_Win32_Ouftap_B{
	meta:
		description = "Trojan:Win32/Ouftap.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 06 00 00 "
		
	strings :
		$a_02_0 = {1d 53 8a 98 90 01 01 a0 40 00 30 1c 32 8b 1d 90 01 01 a0 40 00 40 3b c3 72 02 33 c0 42 3b d7 72 e5 90 00 } //5
		$a_01_1 = {5c 5c 2e 5c 46 61 44 65 76 69 63 65 30 } //1 \\.\FaDevice0
		$a_00_2 = {25 73 5c 31 2e 74 78 74 } //1 %s\1.txt
		$a_00_3 = {74 61 70 69 33 32 64 2e 65 78 65 20 77 61 73 20 6e 6f 74 20 72 61 6e } //1 tapi32d.exe was not ran
		$a_00_4 = {42 69 73 75 6e 69 6e 73 74 2e 62 69 6e } //1 Bisuninst.bin
		$a_00_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 43 72 61 73 68 49 6d 61 67 65 } //1 SYSTEM\CurrentControlSet\Control\CrashImage
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}