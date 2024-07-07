
rule TrojanDropper_Win32_Cutwail_U{
	meta:
		description = "TrojanDropper:Win32/Cutwail.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 68 56 57 be 90 01 04 8d 7d dc a5 a5 a5 a5 6a 03 a4 5e e8 90 01 04 33 d2 6a 19 59 f7 f1 80 c2 61 88 54 35 dc 46 83 fe 0c 72 e7 90 00 } //1
		$a_03_1 = {75 0f 83 0d 90 01 04 01 ff 15 90 01 04 eb 05 a1 90 01 04 69 c0 90 01 04 a3 90 01 04 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}