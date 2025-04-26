
rule TrojanDownloader_Win32_Renos_PT{
	meta:
		description = "TrojanDownloader:Win32/Renos.PT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 c0 81 c0 4d 5a 50 00 } //1
		$a_01_1 = {b8 af ba ff ff f7 d0 } //1
		$a_03_2 = {fb ff ff f7 ?? 83 ?? 04 c7 ?? 00 00 00 00 83 ?? 04 75 f2 ff } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}