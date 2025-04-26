
rule Backdoor_Win32_Zegost_CL{
	meta:
		description = "Backdoor:Win32/Zegost.CL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 %s\%c%c%c%c%c.exe
		$a_01_1 = {25 73 5c 64 61 74 61 2e 6d 64 62 00 } //1
		$a_01_2 = {54 57 39 36 61 57 78 73 59 53 38 30 4c 6a 41 67 4b 47 4e 76 62 58 42 68 64 47 6c 69 62 47 55 70 } //1 TW96aWxsYS80LjAgKGNvbXBhdGlibGUp
		$a_02_3 = {54 46 4d 30 4e [0-04] 2f 66 [0-04] 68 6f 73 74 73 } //1
		$a_00_4 = {2f 00 77 00 77 00 77 00 2e 00 6b 00 6c 00 2e 00 67 00 7a 00 2e 00 63 00 6e 00 2f 00 7e 00 67 00 6c 00 62 00 2f 00 } //1 /www.kl.gz.cn/~glb/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}