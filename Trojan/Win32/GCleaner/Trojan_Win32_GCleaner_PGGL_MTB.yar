
rule Trojan_Win32_GCleaner_PGGL_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ff 01 1e b8 8a a5 08 00 03 45 c4 03 c3 03 c7 89 45 b0 c7 45 a0 16 19 00 00 6a 00 e8 ?? ?? ?? ?? 8b 55 b0 03 55 a0 81 ea 16 19 00 00 2b d0 03 d7 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 03 fa 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d c8 72 ac } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_GCleaner_PGGL_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.PGGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ff 01 33 b8 8a a5 08 00 03 45 d0 03 c6 03 c7 89 45 bc c7 45 ac b2 84 31 00 6a 00 e8 ?? ?? ?? ?? 8b 55 bc 03 55 ac 81 ea b2 84 31 00 2b d7 03 c2 50 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 13 83 c6 04 83 c3 04 3b 75 d4 72 ac } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}