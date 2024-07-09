
rule TrojanDownloader_Win32_Renos_KJ{
	meta:
		description = "TrojanDownloader:Win32/Renos.KJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 00 14 2d 00 90 17 03 05 06 01 ff 75 ?? ff 74 24 ?? 56 (ff 15 ?? ?? ??|?? ff) d0 85 c0 (|) 0f 84 74 } //1
		$a_01_1 = {44 6c 6c 44 65 66 69 6e 65 00 44 6c 6c 52 65 67 } //1 汄䑬晥湩e汄剬来
		$a_03_2 = {40 3d 00 01 00 00 ?? (f1|f4) } //1
		$a_03_3 = {10 68 ff ff ?? ?? 68 ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}