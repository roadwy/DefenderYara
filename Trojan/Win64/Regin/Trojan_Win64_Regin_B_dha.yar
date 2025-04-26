
rule Trojan_Win64_Regin_B_dha{
	meta:
		description = "Trojan:Win64/Regin.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 3b fb 73 1d 8b c7 41 8d 0c 28 ff c5 4a 8d 14 08 83 e0 07 ff c7 8a 04 30 32 c1 30 02 83 fd 08 72 de } //1
		$a_00_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //1 \\.\PhysicalDrive%d
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=10
 
}