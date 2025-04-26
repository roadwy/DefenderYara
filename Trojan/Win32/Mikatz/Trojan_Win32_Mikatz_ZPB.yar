
rule Trojan_Win32_Mikatz_ZPB{
	meta:
		description = "Trojan:Win32/Mikatz.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 4d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 Invoke-Mimikatz
		$a_00_1 = {2d 00 44 00 75 00 6d 00 70 00 43 00 72 00 65 00 64 00 73 00 } //1 -DumpCreds
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}