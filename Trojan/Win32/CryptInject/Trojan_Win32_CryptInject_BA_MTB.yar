
rule Trojan_Win32_CryptInject_BA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 f1 f0 f0 f0 f7 e6 c1 ea 05 8b c2 c1 e0 04 03 c2 03 c0 8b de 2b d8 8b 44 24 90 01 01 03 fe 3b 58 90 01 01 76 90 01 01 e8 90 01 04 8b 44 24 14 83 78 90 01 01 10 72 90 01 01 83 c0 04 8b 00 eb 90 01 01 83 c0 04 8a 0c 18 30 0f 8b 45 90 01 01 2b 45 90 01 01 46 3b f0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}