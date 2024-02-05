
rule Trojan_Win32_Trickbot_STN{
	meta:
		description = "Trojan:Win32/Trickbot.STN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {74 65 6d 70 5c 77 65 62 69 6e 6a 65 63 74 2e 6c 6f 67 } //temp\webinject.log  01 00 
		$a_80_1 = {52 65 6d 6f 76 65 46 46 48 6f 6f 6b 73 } //RemoveFFHooks  01 00 
		$a_80_2 = {49 6e 6a 65 63 74 65 64 20 70 72 6f 63 65 73 73 20 70 69 64 } //Injected process pid  01 00 
		$a_80_3 = {57 65 62 49 6e 6a 65 63 74 20 62 75 69 6c 64 } //WebInject build  00 00 
		$a_00_4 = {5d 04 00 } //00 9b 
	condition:
		any of ($a_*)
 
}