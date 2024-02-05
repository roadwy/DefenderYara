
rule Trojan_Win32_PSWStealer_XH_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 1f 21 c0 81 c6 90 01 04 48 81 e3 90 01 04 21 c0 09 f0 31 19 be 90 01 04 81 ea 90 01 04 41 4e 89 f0 47 81 c2 90 01 04 89 d0 42 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}