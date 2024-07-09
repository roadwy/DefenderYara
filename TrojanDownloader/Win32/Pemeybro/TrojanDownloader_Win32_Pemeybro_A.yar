
rule TrojanDownloader_Win32_Pemeybro_A{
	meta:
		description = "TrojanDownloader:Win32/Pemeybro.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 c3 8d 45 f0 50 68 00 10 00 00 68 ?? ?? ?? ?? ff 75 f8 e8 ?? ?? ?? ?? 85 c0 74 0d 8b 45 f0 85 c0 74 06 c6 45 eb 01 eb 04 c6 45 eb 00 8a 45 eb 84 c0 75 c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}