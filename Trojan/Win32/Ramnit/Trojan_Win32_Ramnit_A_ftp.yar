
rule Trojan_Win32_Ramnit_A_ftp{
	meta:
		description = "Trojan:Win32/Ramnit.A!ftp,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 44 72 69 76 65 00 00 00 00 46 74 70 43 6f 6e 74 72 6f 6c 00 00 00 00 00 00 33 32 62 69 74 20 46 54 50 00 00 00 57 69 6e 53 63 70 00 00 4c 65 61 70 46 74 70 00 } //1
		$a_01_1 = {74 0b 83 78 49 00 74 05 50 ff 50 49 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}