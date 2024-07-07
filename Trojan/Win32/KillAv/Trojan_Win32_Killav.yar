
rule Trojan_Win32_Killav{
	meta:
		description = "Trojan:Win32/Killav,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 4e 6f 77 20 48 61 63 6b 65 64 20 21 21 21 } //1 You Now Hacked !!!
		$a_01_1 = {4e 65 74 20 53 74 6f 70 20 4e 6f 72 74 6f 6e 20 41 6e 74 69 76 69 72 75 73 20 41 75 74 6f 20 50 72 6f 74 65 63 74 20 53 65 72 76 69 63 65 } //1 Net Stop Norton Antivirus Auto Protect Service
		$a_01_2 = {4e 65 74 20 53 74 6f 70 20 6d 63 73 68 69 65 6c 64 } //1 Net Stop mcshield
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}