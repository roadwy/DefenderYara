
rule Trojan_Win32_Redosdru_AB{
	meta:
		description = "Trojan:Win32/Redosdru.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 11 0f be 45 f0 2b d0 8b 4d fc 03 4d f8 88 11 8b 55 fc 03 55 f8 0f be 02 0f be 4d ec 33 c1 8b 55 fc 03 55 f8 88 02 eb bf } //1
		$a_03_1 = {fb ff ff 4d c6 85 ?? fb ff ff 6f c6 85 ?? fb ff ff 7a c6 85 ?? fb ff ff 69 c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 61 c6 85 ?? fb ff ff 2f c6 85 ?? fb ff ff 34 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}