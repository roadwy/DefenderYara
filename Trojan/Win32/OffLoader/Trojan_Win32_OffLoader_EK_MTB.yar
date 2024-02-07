
rule Trojan_Win32_OffLoader_EK_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 09 00 "
		
	strings :
		$a_01_0 = {77 00 61 00 73 00 68 00 64 00 69 00 6e 00 6e 00 65 00 72 00 2e 00 78 00 79 00 7a 00 2f 00 67 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d } //01 00 
		$a_01_1 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65 00 } //00 00  server\share
	condition:
		any of ($a_*)
 
}