
rule Trojan_Win32_CryptInject_PDSK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 45 fd 8a 55 ff 0a c7 8b 5d e8 88 45 fd 88 14 1e 8a 55 fe c7 05 90 01 04 00 00 00 00 88 54 1e 01 81 3d 90 01 04 d8 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}