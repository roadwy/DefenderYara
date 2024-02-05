
rule Trojan_Win32_Cryptinject_PVA_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 7d 0c 00 7c 90 01 01 e8 90 01 04 0f b6 c0 8b 4d 08 03 4d 0c 0f be 11 33 d0 8b 45 08 03 45 0c 88 10 8b 4d 0c 83 e9 01 89 4d 0c eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}