
rule Trojan_Win32_Rootkit_gen_C{
	meta:
		description = "Trojan:Win32/Rootkit.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 04 52 68 4b e1 22 00 50 } //3
		$a_01_1 = {6a 66 51 e8 } //3
		$a_01_2 = {81 e5 00 f0 00 00 81 fd 00 30 00 00 } //3
		$a_00_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //3 KeServiceDescriptorTable
		$a_00_4 = {52 45 53 53 44 54 44 4f 53 } //1 RESSDTDOS
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 65 74 75 70 5c 70 6f 6f 70 } //1 Software\Microsoft\Windows\CurrentVersion\Setup\poop
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=13
 
}