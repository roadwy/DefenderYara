
rule BrowserModifier_Win32_Satrap_bit{
	meta:
		description = "BrowserModifier:Win32/Satrap!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 54 24 18 8b 4c 24 24 c0 e3 04 0a c3 83 c4 08 c0 ea 04 88 45 00 45 32 d0 41 3b f7 88 54 24 10 89 4c 24 1c } //00 00 
	condition:
		any of ($a_*)
 
}