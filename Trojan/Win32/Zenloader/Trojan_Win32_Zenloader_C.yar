
rule Trojan_Win32_Zenloader_C{
	meta:
		description = "Trojan:Win32/Zenloader.C,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //0a 00  rundll32
		$a_00_1 = {2c 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 63 00 6c 00 69 00 65 00 6e 00 74 00 6d 00 61 00 69 00 6e 00 } //00 00  ,platformclientmain
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenloader_C_2{
	meta:
		description = "Trojan:Win32/Zenloader.C,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {70 6c 61 74 66 6f 72 6d 63 6c 69 65 6e 74 6d 61 69 6e } //0a 00  platformclientmain
		$a_01_1 = {72 75 6e 6d 6f 64 75 6c 65 } //0a 00  runmodule
		$a_01_2 = {23 35 30 30 38 23 } //00 00  #5008#
	condition:
		any of ($a_*)
 
}