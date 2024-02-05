
rule Trojan_Win32_LsassDump_G{
	meta:
		description = "Trojan:Win32/LsassDump.G,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 63 00 72 00 65 00 74 00 73 00 64 00 75 00 6d 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}