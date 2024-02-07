
rule TrojanSpy_Win32_Bancos_Lowfi{
	meta:
		description = "TrojanSpy:Win32/Bancos!Lowfi,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 44 00 41 00 4e 00 49 00 45 00 4c 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 74 00 65 00 63 00 6c 00 61 00 64 00 6f 00 73 00 32 00 30 00 30 00 38 00 5c 00 } //01 00  C:\Documents and Settings\DANIEL\Desktop\teclados2008\
		$a_01_1 = {2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 } //01 00  .com.br/
		$a_01_2 = {6d 00 69 00 72 00 63 00 6f 00 73 00 6f 00 66 00 74 00 } //01 00  mircosoft
		$a_01_3 = {42 00 61 00 6e 00 6b 00 } //00 00  Bank
		$a_01_4 = {00 5d 04 00 } //00 f3 
	condition:
		any of ($a_*)
 
}