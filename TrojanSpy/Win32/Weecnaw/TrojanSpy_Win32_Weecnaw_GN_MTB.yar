
rule TrojanSpy_Win32_Weecnaw_GN_MTB{
	meta:
		description = "TrojanSpy:Win32/Weecnaw.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {06 13 0b 11 04 11 06 11 0a 58 11 09 11 0a 91 11 0b 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d8 } //1
		$a_02_1 = {04 1f 1d 7e 90 01 03 04 6f 90 01 03 0a 0a 02 4a 06 6f 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}