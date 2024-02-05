
rule Trojan_Win32_Redosdru_Z_bit{
	meta:
		description = "Trojan:Win32/Redosdru.Z!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {fb ff ff 4d c6 85 90 01 01 fb ff ff 6f c6 85 90 01 01 fb ff ff 7a c6 85 90 01 01 fb ff ff 69 c6 85 90 01 01 fb ff ff 6c c6 85 90 01 01 fb ff ff 6c c6 85 90 01 01 fb ff ff 61 c6 85 90 01 01 fb ff ff 2f c6 85 90 01 01 fb ff ff 34 90 00 } //01 00 
		$a_01_1 = {0f be 11 2b d0 8b 45 ec 03 45 e8 88 10 0f be 4d dc 8b 55 ec 03 55 e8 0f be 02 33 c1 8b 4d ec 03 4d e8 88 01 eb bf } //00 00 
	condition:
		any of ($a_*)
 
}