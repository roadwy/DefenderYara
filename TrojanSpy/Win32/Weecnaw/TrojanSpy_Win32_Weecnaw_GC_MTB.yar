
rule TrojanSpy_Win32_Weecnaw_GC_MTB{
	meta:
		description = "TrojanSpy:Win32/Weecnaw.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {33 c9 8d 1c 01 30 13 41 81 f9 } //1
		$a_02_1 = {80 34 01 70 90 02 10 41 89 d3 90 02 20 39 d9 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}