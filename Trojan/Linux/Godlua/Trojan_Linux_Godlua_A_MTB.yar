
rule Trojan_Linux_Godlua_A_MTB{
	meta:
		description = "Trojan:Linux/Godlua.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 83 ec 1c 6a 00 8d 44 24 14 50 e8 8f e7 ff ff 8b 7c 24 1c b9 d3 4d 62 10 89 f8 c1 ff 1f f7 e9 b9 e8 03 00 00 89 c8 89 d6 f7 6c 24 18 c1 fe 06 29 fe 89 f7 c1 ff 1f 01 f0 11 fa 83 c4 24 5e 5f c3 } //01 00 
		$a_00_1 = {64 2e 68 65 68 65 64 61 2e 74 6b } //01 00  d.heheda.tk
		$a_00_2 = {66 6c 61 73 68 2e 62 61 74 } //01 00  flash.bat
		$a_00_3 = {73 73 6c 5f 77 72 69 74 65 5f 72 65 63 6f 72 64 } //00 00  ssl_write_record
	condition:
		any of ($a_*)
 
}