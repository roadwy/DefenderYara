
rule Trojan_Win32_MinerCrypt_SN_MTB{
	meta:
		description = "Trojan:Win32/MinerCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 8b 3c 24 83 c4 04 29 c0 21 c0 21 f6 e8 90 01 01 00 00 00 21 f0 46 09 c6 31 3a 89 f0 21 c6 42 29 f0 81 e8 90 01 04 21 c6 39 da 75 90 01 01 81 c0 90 01 04 48 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}