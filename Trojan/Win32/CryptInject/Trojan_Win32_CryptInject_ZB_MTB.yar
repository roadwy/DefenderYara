
rule Trojan_Win32_CryptInject_ZB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c6 f7 f1 8b 45 90 01 01 8a 0c 02 8d 14 3e 8b 45 90 01 01 46 8a 04 10 32 c1 88 02 3b f3 72 90 00 } //01 00 
		$a_01_1 = {64 00 6f 00 63 00 2d 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00 } //00 00  doc-scan.exe
	condition:
		any of ($a_*)
 
}