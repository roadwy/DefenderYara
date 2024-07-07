
rule TrojanDropper_Win32_Cefyns_B{
	meta:
		description = "TrojanDropper:Win32/Cefyns.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {d0 07 72 06 66 81 45 90 01 01 30 f8 8d 85 64 90 01 01 ff ff 90 00 } //1
		$a_03_1 = {72 0e 8a 08 80 f9 90 01 01 74 07 80 f1 90 01 01 88 08 eb e7 90 00 } //1
		$a_01_2 = {c6 85 6c fd ff ff 54 ff d3 50 8d 85 64 fe ff ff 50 6a 01 } //1
		$a_01_3 = {5c 6e 76 73 76 63 31 30 32 34 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}