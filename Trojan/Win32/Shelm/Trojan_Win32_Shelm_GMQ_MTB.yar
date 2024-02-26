
rule Trojan_Win32_Shelm_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Shelm.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 10 2b 45 f4 c7 44 24 90 01 05 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24 e8 90 01 04 83 ec 10 89 45 ec 8b 45 ec 01 45 f0 8b 45 ec 01 45 f4 83 7d ec ff 90 01 02 c7 44 24 90 01 01 6e 50 40 00 8b 45 08 89 04 24 90 00 } //01 00 
		$a_01_1 = {64 7a 33 2e 64 64 6e 73 2e 6e 65 74 } //00 00  dz3.ddns.net
	condition:
		any of ($a_*)
 
}