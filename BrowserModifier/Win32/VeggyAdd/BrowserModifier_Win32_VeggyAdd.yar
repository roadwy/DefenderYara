
rule BrowserModifier_Win32_VeggyAdd{
	meta:
		description = "BrowserModifier:Win32/VeggyAdd,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 5c 00 73 00 74 00 61 00 67 00 65 00 64 00 5c 00 } //1 \extensions\staged\
		$a_03_1 = {65 78 74 65 6e 64 5f 90 0f 04 00 2e 65 78 65 00 [0-0f] 00 65 3d 64 6f 77 6e 6c 6f 61 64 65 6e 64 26 73 3d [0-09] 26 69 3d [0-09] 26 76 3d 90 10 04 00 2e 90 10 04 00 2e 90 10 04 00 2e 90 10 04 00 26 65 63 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}