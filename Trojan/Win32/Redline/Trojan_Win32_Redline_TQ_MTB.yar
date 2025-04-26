
rule Trojan_Win32_Redline_TQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.TQ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 } //1
		$a_01_1 = {c1 e9 05 03 4d e8 8b da c1 e3 04 03 5d e4 8d 04 16 33 cb 33 c8 89 45 f8 89 4d 0c 8b 45 0c 01 05 bc 61 c4 02 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 45 e0 89 45 f4 8b 45 08 03 45 f0 89 45 f8 8b 45 08 83 0d c4 61 c4 02 ff c1 e8 05 c7 05 c0 61 c4 02 19 36 6b ff 89 45 0c 8b 45 dc 01 45 0c ff 75 f8 8d 45 f4 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}