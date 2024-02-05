
rule Trojan_Win32_VB_AHC{
	meta:
		description = "Trojan:Win32/VB.AHC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6d 43 6f 6f 6b 69 65 41 6e 64 43 61 63 68 65 00 90 01 11 00 00 00 6d 6f 64 45 6e 61 62 6c 65 50 72 69 76 69 6c 65 67 65 00 00 90 01 11 00 00 00 6d 4c 6f 63 61 6c 4d 41 43 90 01 14 00 00 00 6d 6f 64 48 6f 6f 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}