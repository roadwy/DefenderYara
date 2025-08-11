
rule Trojan_Win32_GCleaner_SPGK_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.SPGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 ac 03 75 ec 03 f0 bf 89 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 fe 81 ef 89 15 00 00 03 c7 50 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 13 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 c3 8b 45 ec 3b 45 dc 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}