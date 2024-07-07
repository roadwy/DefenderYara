
rule Trojan_Win32_Killav_FM{
	meta:
		description = "Trojan:Win32/Killav.FM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 76 00 6d 00 6f 00 6e 00 64 00 00 00 73 00 66 00 63 00 74 00 6c 00 63 00 6f 00 6d 00 00 00 00 00 6d 00 70 00 6d 00 6f 00 6e 00 00 00 74 00 77 00 69 00 73 00 74 00 65 00 72 00 } //1
		$a_01_1 = {c6 45 e1 27 c6 45 e2 f6 c6 45 e3 36 c6 45 e4 56 c6 45 e5 37 c6 45 e6 37 c6 45 e7 33 c6 45 e8 23 c6 45 e9 64 c6 45 ea 96 c6 45 eb 27 c6 45 ec 37 c6 45 ed 47 c6 45 ee 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}