
rule Trojan_Win32_Necurs_A{
	meta:
		description = "Trojan:Win32/Necurs.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 5c 00 2e 00 5c 00 4e 00 74 00 53 00 65 00 63 00 75 00 72 00 65 00 53 00 79 00 73 00 } //1 \\.\NtSecureSys
		$a_01_1 = {8d 14 90 03 d2 c1 ce 0d 33 f2 03 c6 88 19 41 ff 4d 0c 75 e1 } //1
		$a_03_2 = {35 de c0 ad de 89 45 ?? ff 15 ?? ?? ?? ?? 33 45 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}