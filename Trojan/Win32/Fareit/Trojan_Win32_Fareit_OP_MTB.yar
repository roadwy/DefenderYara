
rule Trojan_Win32_Fareit_OP_MTB{
	meta:
		description = "Trojan:Win32/Fareit.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 89 45 f4 8b 45 fc 90 03 45 f8 90 8a 18 90 80 f3 e6 88 18 90 90 ff 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_OP_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d f3 fc d6 7a 7a 7a 92 c5 8e 85 85 12 21 0f f0 8a 2d f3 3c 36 92 cb 8e 85 85 f1 a2 12 1e fc 89 0f 2d f3 24 32 92 db 8e 85 85 f3 3c 4e 12 d8 dc 1b 91 2d 92 e9 8e 85 85 12 af 35 1e 58 2d f3 3c 42 92 ff 8e 85 85 12 03 54 b9 ee 2d f3 3c 46 92 0d 8e 85 85 12 cb 72 7e 8d 2d 93 39 9c 85 85 ea ea } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}