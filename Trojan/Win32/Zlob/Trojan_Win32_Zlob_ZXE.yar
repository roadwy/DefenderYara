
rule Trojan_Win32_Zlob_ZXE{
	meta:
		description = "Trojan:Win32/Zlob.ZXE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 cc 40 89 45 cc 8b 45 cc 3b 45 d0 73 34 8b 8d 48 ff ff ff e8 ?? ?? ff ff 66 89 45 c8 0f b7 45 c8 35 ?? ?? 00 00 50 6a 01 8d 4d d4 e8 70 01 00 00 8b 85 48 ff ff ff 83 c0 04 89 85 48 ff ff ff eb bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}