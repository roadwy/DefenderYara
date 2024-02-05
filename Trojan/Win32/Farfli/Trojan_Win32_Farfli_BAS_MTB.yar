
rule Trojan_Win32_Farfli_BAS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 83 c1 01 89 4d f0 83 7d f0 10 7d 1b 8b 55 f0 0f b6 44 15 a4 8b 4d f0 0f be 54 0d c0 33 d0 8b 45 f0 88 54 05 c0 eb } //00 00 
	condition:
		any of ($a_*)
 
}