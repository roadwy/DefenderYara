
rule Trojan_Win32_Zonsterarch_R{
	meta:
		description = "Trojan:Win32/Zonsterarch.R,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b d2 44 81 fa 52 02 00 00 76 11 8b 45 f8 69 c0 87 61 01 00 8b 4d f0 03 c8 89 4d f8 } //00 00 
	condition:
		any of ($a_*)
 
}