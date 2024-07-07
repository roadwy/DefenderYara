
rule Worm_Win32_Nekav_C{
	meta:
		description = "Worm:Win32/Nekav.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 4f 70 } //1
		$a_01_1 = {43 31 4f 65 44 6d 38 31 36 57 37 4b 7a 4c 2f 4d 6e 36 57 63 36 55 46 00 } //1 ㅃ敏浄ㄸ圶䬷䱺䴯㙮捗唶F
		$a_03_2 = {fe 45 ff 80 7d ff 5b 0f 85 90 01 04 33 c0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}