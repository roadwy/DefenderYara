
rule TrojanDownloader_Win32_Skidlo_A{
	meta:
		description = "TrojanDownloader:Win32/Skidlo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c1 c2 03 32 17 47 80 3f 00 75 f5 } //1
		$a_03_1 = {ff ff 02 00 01 00 90 09 04 00 c7 85 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}