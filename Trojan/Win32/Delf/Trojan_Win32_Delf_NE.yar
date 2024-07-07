
rule Trojan_Win32_Delf_NE{
	meta:
		description = "Trojan:Win32/Delf.NE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 07 68 84 00 00 00 eb 05 68 85 00 00 00 } //1
		$a_01_1 = {c1 e0 10 2b c3 99 f7 ff } //1
		$a_01_2 = {25 01 00 00 80 79 05 48 83 c8 fe 40 } //1
		$a_01_3 = {5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 \policies\Explorer\Run
		$a_01_4 = {25 73 2f 55 70 64 61 74 65 46 69 6c 65 73 2f 75 70 64 61 74 65 25 64 2e 65 78 65 } //1 %s/UpdateFiles/update%d.exe
		$a_01_5 = {2f 75 70 64 61 74 65 2e 61 73 70 78 3f 66 65 65 64 62 61 63 6b 3d 73 75 63 63 65 73 73 26 76 65 72 3d 25 64 } //1 /update.aspx?feedback=success&ver=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}