
rule Trojan_Win32_LoaderMulti_RD_MTB{
	meta:
		description = "Trojan:Win32/LoaderMulti.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {55 57 56 53 8b 6c 24 14 8b 74 24 18 8b 7c 24 1c 85 ff 74 3e b9 00 00 00 00 89 c8 ba 00 00 00 00 f7 74 24 20 c1 ea 02 0f be 5c 15 00 6b db 57 b8 ed 73 48 4d f7 eb 89 d0 c1 f8 04 c1 fb 1f 29 d8 ba 9a ff ff ff 0f af c2 30 04 0e 83 c1 01 39 f9 75 c7 5b 5e 5f 5d c3 b8 81 01 00 00 c3 } //00 00 
	condition:
		any of ($a_*)
 
}