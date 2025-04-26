
rule PWS_Win32_Frethog_X{
	meta:
		description = "PWS:Win32/Frethog.X,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 } //1 ElementClient.exe
		$a_01_1 = {77 32 69 2e 63 6f 6d 2e 63 6e } //1 w2i.com.cn
		$a_01_2 = {43 52 41 43 4b 49 4e 47 } //1 CRACKING
		$a_01_3 = {6d 69 62 61 6f 2e 61 73 70 } //1 mibao.asp
		$a_00_4 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}