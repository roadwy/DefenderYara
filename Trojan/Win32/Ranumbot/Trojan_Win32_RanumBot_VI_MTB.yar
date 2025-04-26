
rule Trojan_Win32_RanumBot_VI_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 57 68 6a 75 51 69 78 54 4b 6c 64 55 72 68 55 77 58 57 62 4a } //1 Go build ID: "WhjuQixTKldUrhUwXWbJ
		$a_01_1 = {61 43 46 56 32 7a 55 35 39 45 34 61 64 58 54 2f 53 4c 4f 55 67 70 30 4f 6f 4e 6f 52 6e 6a 51 72 7a 5a 62 52 2f 6c 6a 7a 65 73 69 48 32 73 58 59 52 7a 30 68 34 35 48 77 67 } //1 aCFV2zU59E4adXT/SLOUgp0OoNoRnjQrzZbR/ljzesiH2sXYRz0h45Hwg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}