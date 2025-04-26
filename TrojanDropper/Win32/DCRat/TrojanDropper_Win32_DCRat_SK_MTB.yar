
rule TrojanDropper_Win32_DCRat_SK_MTB{
	meta:
		description = "TrojanDropper:Win32/DCRat.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 52 65 6e 61 6d 65 5d } //1 [Rename]
		$a_01_1 = {25 73 25 73 2e 64 6c 6c } //1 %s%s.dll
		$a_01_2 = {43 3a 5c 54 45 4d 50 5c 64 61 6c 2e 65 78 65 } //1 C:\TEMP\dal.exe
		$a_01_3 = {5c 6d 6e 62 2e 65 78 65 } //1 \mnb.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}