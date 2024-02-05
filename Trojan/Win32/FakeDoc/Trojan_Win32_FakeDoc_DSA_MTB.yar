
rule Trojan_Win32_FakeDoc_DSA_MTB{
	meta:
		description = "Trojan:Win32/FakeDoc.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c8 83 e1 03 8a 91 64 fb 90 01 02 8a 8c 06 28 0e 90 01 02 32 ca 88 88 28 0e 90 01 02 75 90 01 01 88 90 01 05 40 3b c7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}