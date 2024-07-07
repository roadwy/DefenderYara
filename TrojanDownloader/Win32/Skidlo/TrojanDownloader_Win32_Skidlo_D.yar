
rule TrojanDownloader_Win32_Skidlo_D{
	meta:
		description = "TrojanDownloader:Win32/Skidlo.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 c2 03 32 d0 eb ea 8b 75 08 ad 3b c2 75 03 43 eb 1e } //1
		$a_01_1 = {c1 e9 02 f3 a5 0f b7 53 06 8d 83 f8 00 00 00 } //1
		$a_01_2 = {ac 32 c2 42 aa e2 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}