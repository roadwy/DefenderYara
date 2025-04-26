
rule TrojanDownloader_Win32_Chepvil_B{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 eb 06 8d 3f d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 ?? ?? 83 c4 ec 53 56 57 ff 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}