
rule Trojan_Win32_Guloader_SIBU5_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU5!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 6f 6d 6d 61 6e 64 6f 6c 69 6e 6a 65 72 6e 65 73 } //01 00  Kommandolinjernes
		$a_03_1 = {89 c7 0f fd fa 90 08 c2 02 be 90 01 04 90 08 5c 02 31 d2 90 08 48 02 31 c9 90 08 76 02 33 0c 16 90 08 dd 02 81 f1 90 01 04 90 08 45 02 31 0c 17 90 08 c0 02 81 c2 90 01 04 90 08 ec 01 81 ea 90 01 04 90 08 e1 02 81 fa 90 01 04 90 02 5a 0f 85 90 01 04 90 08 a6 02 59 90 08 59 02 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}