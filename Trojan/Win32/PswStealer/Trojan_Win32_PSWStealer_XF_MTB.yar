
rule Trojan_Win32_PSWStealer_XF_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 18 29 ca f7 d7 81 e3 90 01 04 4a f7 d2 29 d7 31 1e 21 cf 47 46 4f bf 90 01 04 40 29 ca 81 c7 90 01 04 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}