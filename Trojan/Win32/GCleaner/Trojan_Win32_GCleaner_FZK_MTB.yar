
rule Trojan_Win32_GCleaner_FZK_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.FZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8b 55 ec 01 13 8b 55 d4 03 55 ac 03 55 ec 03 c2 ba 89 15 00 00 03 d0 81 ea 89 15 00 00 31 13 83 45 ?? 04 83 c3 04 8b 45 ec 3b 45 dc 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}