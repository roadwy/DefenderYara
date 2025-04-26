
rule Trojan_Win32_VB_TK{
	meta:
		description = "Trojan:Win32/VB.TK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d f8 06 0e 00 1e 6f 03 00 02 00 07 0a 0f 00 00 00 00 07 0a 0b 00 00 00 00 3d f5 00 00 00 00 f5 00 00 00 00 04 1c ff fe 8e 01 00 00 00 10 00 80 08 28 40 ff e8 03 f5 00 00 00 00 6c 1c ff 52 04 1c ff 94 08 00 98 00 94 08 00 34 00 0a 08 00 0c 00 04 1c ff 5a 00 07 0a 0b 00 00 00 00 0d 05 10 00 24 11 00 0d f8 06 12 00 } //1
		$a_01_1 = {fd e7 08 00 94 01 36 0a 00 54 ff 44 ff 34 ff 24 ff 14 ff 00 10 27 54 ff 0b 1a 00 04 00 70 6a ff 35 54 ff 00 2e 04 fc fe 04 00 ff 05 00 00 24 01 00 0d 14 00 02 00 08 00 ff 0d 50 00 03 00 6c fc fe 4a f5 03 00 00 00 c7 2f fc fe 1a 00 ff 1c 56 01 00 c0 04 fc fe 04 00 ff 05 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}