
rule Trojan_Win32_CryptInject_YL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 5a 90 8b 15 e8 1d 47 00 8a 92 38 44 46 00 88 15 f0 1d 47 00 8b d6 03 d3 89 15 e0 1d 47 00 30 05 f0 1d 47 00 90 90 a1 e0 1d 47 00 8a 15 f0 1d 47 00 88 10 90 90 83 05 e8 1d 47 00 02 43 81 fb 5d 5b 00 00 75 ba } //00 00 
	condition:
		any of ($a_*)
 
}