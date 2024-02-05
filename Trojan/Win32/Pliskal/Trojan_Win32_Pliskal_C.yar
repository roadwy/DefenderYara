
rule Trojan_Win32_Pliskal_C{
	meta:
		description = "Trojan:Win32/Pliskal.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 51 00 75 00 61 00 6e 00 74 00 22 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}