
rule Trojan_Win32_Delf_MK{
	meta:
		description = "Trojan:Win32/Delf.MK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 61 73 6b 6d 67 72 73 [0-08] 53 74 61 72 74 } //1
		$a_01_1 = {3a 61 64 65 6c } //1 :adel
		$a_01_2 = {63 68 6f 69 63 65 20 2f 74 20 35 20 2f 64 20 79 } //1 choice /t 5 /d y
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}