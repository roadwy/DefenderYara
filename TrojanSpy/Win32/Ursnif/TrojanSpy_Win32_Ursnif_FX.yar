
rule TrojanSpy_Win32_Ursnif_FX{
	meta:
		description = "TrojanSpy:Win32/Ursnif.FX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 5f f3 6e 3c 6a 27 33 ff 5b 89 01 66 89 45 f2 33 d2 69 c0 0d 66 19 00 05 5f f3 6e 3c 88 44 15 f4 42 83 fa 08 72 eb } //1
		$a_00_1 = {2f 73 64 20 25 6c 75 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}