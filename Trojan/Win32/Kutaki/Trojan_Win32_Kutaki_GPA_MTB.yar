
rule Trojan_Win32_Kutaki_GPA_MTB{
	meta:
		description = "Trojan:Win32/Kutaki.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {75 4e 65 77 42 69 74 6d 61 70 49 6d 61 67 65 2e 62 6d 70 } //uNewBitmapImage.bmp  5
		$a_80_1 = {61 48 52 30 63 44 6f 76 4c 32 35 6c 64 32 78 70 62 6d 74 33 62 33 52 76 62 47 39 32 5a 53 35 6a 62 48 56 69 4c 32 78 76 64 6d 55 76 64 47 68 79 5a 57 55 75 63 47 68 77 } //aHR0cDovL25ld2xpbmt3b3RvbG92ZS5jbHViL2xvdmUvdGhyZWUucGhw  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}