
rule PWS_Win32_Fareit_RT_MTB{
	meta:
		description = "PWS:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 2c 00 2d 00 32 00 31 00 38 00 31 00 33 00 } //01 00  @shell32.dll,-21813
		$a_01_1 = {65 00 6d 00 67 00 6b 00 67 00 74 00 67 00 6e 00 6e 00 6d 00 6e 00 6d 00 6e 00 69 00 6e 00 69 00 67 00 74 00 68 00 6b 00 67 00 6f 00 67 00 67 00 67 00 76 00 6d 00 6b 00 68 00 69 00 6e 00 6a 00 67 00 67 00 6e 00 76 00 6d 00 } //01 00  emgkgtgnnmnmninigthkgogggvmkhinjggnvm
		$a_01_2 = {41 00 72 00 76 00 69 00 40 00 53 00 65 00 68 00 6d 00 69 00 2e 00 6f 00 72 00 67 00 2e 00 75 00 6b 00 } //01 00  Arvi@Sehmi.org.uk
		$a_01_3 = {77 00 77 00 77 00 2e 00 41 00 72 00 76 00 69 00 6e 00 64 00 65 00 72 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00 } //00 00  www.Arvinder.co.uk
	condition:
		any of ($a_*)
 
}