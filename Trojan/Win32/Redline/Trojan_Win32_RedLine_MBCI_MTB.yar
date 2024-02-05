
rule Trojan_Win32_RedLine_MBCI_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 33 b2 3d 6e f7 64 24 68 8b 44 24 68 81 6c 24 68 b6 93 e6 65 81 44 24 68 db e8 e4 21 81 6c 24 68 9d c0 11 1f 81 44 24 68 91 88 05 3d b8 c1 04 90 7b f7 a4 24 8c 00 00 00 8b 84 24 8c 00 00 00 81 44 24 68 7b 3f f1 7a b8 32 b7 31 5b f7 a4 24 8c 00 00 00 8b 84 24 8c 00 00 00 b8 0c 61 e9 32 f7 64 24 30 8b 44 24 30 81 6c 24 68 62 29 f6 1a 81 6c 24 30 22 ef 9d 05 81 6c 24 68 a3 88 87 4f b8 ac 4f 2a 4b f7 a4 24 88 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}