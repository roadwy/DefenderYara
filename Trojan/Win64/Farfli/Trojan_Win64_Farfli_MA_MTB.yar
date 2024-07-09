
rule Trojan_Win64_Farfli_MA_MTB{
	meta:
		description = "Trojan:Win64/Farfli.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 83 64 24 20 00 4c 8d 05 ?? ?? ?? ?? 45 33 c9 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15 } //5
		$a_01_1 = {41 6c 69 62 61 62 61 69 73 53 42 5c 6d 69 61 6e 2e 65 78 65 } //1 AlibabaisSB\mian.exe
		$a_01_2 = {3a 2f 2f 34 33 2e 31 34 32 2e 31 38 37 2e 32 30 33 2f } //1 ://43.142.187.203/
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {52 74 6c 43 61 70 74 75 72 65 43 6f 6e 74 65 78 74 } //1 RtlCaptureContext
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}