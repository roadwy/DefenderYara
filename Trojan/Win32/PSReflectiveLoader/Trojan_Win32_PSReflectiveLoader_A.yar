
rule Trojan_Win32_PSReflectiveLoader_A{
	meta:
		description = "Trojan:Win32/PSReflectiveLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 72 75 6e 6e 65 72 2e 70 6f 77 65 72 73 68 65 6c 6c 72 75 6e 6e 65 72 } //powershellrunner.powershellrunner  01 00 
		$a_80_1 = {64 66 63 34 65 65 62 62 2d 37 33 38 34 2d 34 64 62 35 2d 39 62 61 64 2d 32 35 37 32 30 33 30 32 39 62 64 39 } //dfc4eebb-7384-4db5-9bad-257203029bd9  01 00 
		$a_80_2 = {75 6e 6d 61 6e 61 67 65 64 70 6f 77 65 72 73 68 65 6c 6c 2d 72 64 69 2e 64 6c 6c } //unmanagedpowershell-rdi.dll  01 00 
		$a_80_3 = {72 75 6e 74 69 6d 65 63 6c 72 68 6f 73 74 3a 3a 67 65 74 63 75 72 72 65 6e 74 61 70 70 64 6f 6d 61 69 6e 69 64 20 66 61 69 6c 65 64 } //runtimeclrhost::getcurrentappdomainid failed  01 00 
		$a_80_4 = {69 6e 76 6f 6b 65 70 73 } //invokeps  00 00 
	condition:
		any of ($a_*)
 
}