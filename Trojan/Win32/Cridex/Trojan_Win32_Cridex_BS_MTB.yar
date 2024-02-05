
rule Trojan_Win32_Cridex_BS_MTB{
	meta:
		description = "Trojan:Win32/Cridex.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 50 11 00 00 ff 15 90 01 04 03 f0 68 50 11 00 00 ff 15 90 01 04 03 f0 68 50 11 00 00 ff 15 90 01 04 03 f0 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8a 0c 31 88 0c 10 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}