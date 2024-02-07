
rule Trojan_Win32_NSISInjector_EK_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 68 00 6f 00 6f 00 65 00 79 00 5c 00 53 00 6c 00 61 00 67 00 73 00 62 00 72 00 6f 00 64 00 65 00 72 00 65 00 6e 00 2e 00 6c 00 6e 00 6b 00 } //01 00  Phooey\Slagsbroderen.lnk
		$a_01_1 = {62 00 61 00 74 00 74 00 65 00 72 00 79 00 2e 00 70 00 6e 00 67 00 } //01 00  battery.png
		$a_01_2 = {63 00 61 00 6c 00 6c 00 2d 00 73 00 74 00 6f 00 70 00 2d 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 69 00 63 00 2e 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 69 00 63 00 2e 00 70 00 6e 00 67 00 } //01 00  call-stop-symbolic.symbolic.png
		$a_01_3 = {42 00 69 00 73 00 6b 00 6f 00 70 00 70 00 65 00 6c 00 69 00 67 00 } //01 00  Biskoppelig
		$a_01_4 = {66 00 6f 00 6c 00 64 00 65 00 72 00 2d 00 73 00 61 00 76 00 65 00 64 00 2d 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 70 00 6e 00 67 00 } //00 00  folder-saved-search.png
	condition:
		any of ($a_*)
 
}