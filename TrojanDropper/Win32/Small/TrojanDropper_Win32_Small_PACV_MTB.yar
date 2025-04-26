
rule TrojanDropper_Win32_Small_PACV_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.PACV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 f6 5f 5b 74 1e 90 0f b6 11 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 68 ed 41 00 83 c1 01 83 ee 01 75 e3 } //1
		$a_01_1 = {49 6e 66 65 63 74 65 64 } //1 Infected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}