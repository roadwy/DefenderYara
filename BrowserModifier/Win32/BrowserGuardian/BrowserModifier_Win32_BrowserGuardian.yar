
rule BrowserModifier_Win32_BrowserGuardian{
	meta:
		description = "BrowserModifier:Win32/BrowserGuardian,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 42 00 35 00 44 00 43 00 33 00 37 00 39 00 2d 00 45 00 44 00 30 00 36 00 2d 00 34 00 35 00 35 00 32 00 2d 00 41 00 37 00 33 00 36 00 2d 00 34 00 31 00 34 00 41 00 31 00 35 00 37 00 30 00 43 00 32 00 34 00 46 00 } //1 4B5DC379-ED06-4552-A736-414A1570C24F
		$a_01_1 = {4f 00 6f 00 70 00 73 00 2c 00 20 00 73 00 6f 00 6d 00 65 00 74 00 68 00 69 00 6e 00 67 00 20 00 63 00 68 00 61 00 6e 00 67 00 65 00 64 00 20 00 69 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 70 00 72 00 6f 00 78 00 79 00 20 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 } //1 Oops, something changed in your proxy settings
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}