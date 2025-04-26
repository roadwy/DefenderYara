
rule TrojanProxy_Win32_Banker_V{
	meta:
		description = "TrojanProxy:Win32/Banker.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c [0-0c] 68 74 74 70 3a 2f 2f 63 6f 6c 65 67 69 6f 62 6f 62 73 2e 63 6f 6d 2f 66 65 6c 69 63 69 64 61 64 65 2f 73 65 63 72 65 74 2e 70 61 63 } //2
		$a_00_1 = {2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 2f 46 } //1 /IM iexplore.exe /F
		$a_00_2 = {2f 49 4d 20 66 69 72 65 66 6f 78 2e 65 78 65 20 2f 46 } //1 /IM firefox.exe /F
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}