
rule Trojan_Win32_Farfli_AD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 65 43 61 6e 63 65 72 32 30 30 39 } //1 PeCancer2009
		$a_01_1 = {43 3a 5c 6d 79 73 65 6c 66 2e 64 6c 6c } //1 C:\myself.dll
		$a_01_2 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 46 69 72 6d 77 61 72 65 54 61 62 6c 65 } //1 GetSystemFirmwareTable
		$a_01_4 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 57 } //1 Control_RunDLLW
		$a_01_5 = {48 6c 4d 61 69 6e 2e 64 6c 6c } //1 HlMain.dll
		$a_00_6 = {62 62 62 62 62 62 62 62 62 62 00 63 63 63 63 63 } //1 扢扢扢扢扢挀捣捣
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}