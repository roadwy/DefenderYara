
rule Trojan_Win32_Delf_KQ{
	meta:
		description = "Trojan:Win32/Delf.KQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 6e 74 6c 64 72 2e 64 6c 6c } //04 00  \Microsoft\ntldr.dll
		$a_01_1 = {ff ff ff ff 05 00 00 00 53 54 20 2f 31 00 00 00 ff ff ff ff 03 00 00 00 73 74 65 00 ff ff ff ff 03 00 00 00 6d 61 69 00 ff ff ff ff 03 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}