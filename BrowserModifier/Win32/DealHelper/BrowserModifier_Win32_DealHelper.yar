
rule BrowserModifier_Win32_DealHelper{
	meta:
		description = "BrowserModifier:Win32/DealHelper,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 64 73 31 2e 64 65 61 6c 68 65 6c 70 65 72 2e 63 6f 6d } //01 00 
		$a_01_1 = {52 65 64 69 72 65 63 74 53 79 73 74 65 6d 2f 55 52 4c 4c 49 4e 4b 2f 44 45 4c 45 54 45 } //01 00 
		$a_01_2 = {75 73 65 72 69 64 3d 25 68 53 26 6c 64 3d 25 68 53 } //00 00 
	condition:
		any of ($a_*)
 
}