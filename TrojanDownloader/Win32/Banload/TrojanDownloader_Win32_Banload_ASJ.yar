
rule TrojanDownloader_Win32_Banload_ASJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 e2 fe fe fa b0 a5 a5 } //1
		$a_01_1 = {00 41 6c 72 55 6e 65 70 4f 74 65 6e 72 65 74 6e 49 00 } //1 䄀牬湕灥瑏湥敲湴I
		$a_01_2 = {00 c2 c5 c7 cf ce d8 c3 dc cf 00 } //1
		$a_03_3 = {ba 89 8a 01 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff } //1
		$a_03_4 = {33 d2 8a 55 ?? 8b 4d ?? 8a 54 11 ff 8b ce c1 e9 08 32 d1 e8 ?? ?? ff ff 8b 55 ?? 8d 45 ?? e8 ?? ?? ff ff fe 45 ?? fe cb 75 d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}