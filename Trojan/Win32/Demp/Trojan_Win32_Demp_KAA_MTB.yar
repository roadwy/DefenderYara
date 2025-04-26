
rule Trojan_Win32_Demp_KAA_MTB{
	meta:
		description = "Trojan:Win32/Demp.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0f 8d 49 01 32 c2 80 c2 05 88 41 ff 83 ee 01 75 ed } //10
		$a_01_1 = {4c 69 76 69 6e 67 4f 66 66 54 68 65 4c 61 6e 64 2e 70 64 62 } //1 LivingOffTheLand.pdb
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run\
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}