
rule TrojanDropper_Win32_Dozmot_B{
	meta:
		description = "TrojanDropper:Win32/Dozmot.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 05 bb f0 9b 5b 00 } //1
		$a_01_1 = {75 07 bb 24 ad 5b 00 eb 04 } //1
		$a_01_2 = {44 69 76 78 44 65 63 6f 64 65 72 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}