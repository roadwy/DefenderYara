
rule Trojan_Win32_Ramnit_D{
	meta:
		description = "Trojan:Win32/Ramnit.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 f0 68 2e 73 79 73 56 6a } //1
		$a_01_1 = {74 68 40 c6 00 5c 40 c6 00 00 6a 00 8f 85 } //1
		$a_01_2 = {52 61 70 70 6f 72 74 4d 67 6d 74 } //1 RapportMgmt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}