
rule Worm_Win32_Skypii_A{
	meta:
		description = "Worm:Win32/Skypii.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 74 00 53 00 6b 00 4d 00 61 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 2e 00 55 00 6e 00 69 00 63 00 6f 00 64 00 65 00 43 00 6c 00 61 00 73 00 73 00 00 00 } //1
		$a_03_1 = {6a 00 6a 09 68 00 01 00 00 52 ff d7 6a 90 01 01 ff d6 6a 00 6a 02 6a 00 6a 10 ff d3 6a 90 01 01 ff d6 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}