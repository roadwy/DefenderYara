
rule Trojan_Win32_Loader_ZZ{
	meta:
		description = "Trojan:Win32/Loader.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 8b 55 fc 68 20 30 2d 6d 8f 45 f4 68 61 57 7a 74 8f 45 f0 8d 82 90 01 04 ff d0 54 ff d0 8b d8 8b 55 fc 68 20 30 2d 6d 8f 45 f4 68 65 1d 22 74 8f 45 f0 8d 82 90 01 04 ff d0 54 53 ff d0 85 c0 75 fc 58 48 75 b8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}