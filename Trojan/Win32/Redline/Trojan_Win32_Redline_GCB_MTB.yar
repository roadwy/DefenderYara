
rule Trojan_Win32_Redline_GCB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 83 e0 03 8a b8 90 01 04 32 fb 8b 45 dc 8a 1c 30 a1 90 01 04 8b 48 04 81 c1 90 01 04 8b 01 25 90 01 04 0d 90 01 04 89 01 b9 90 01 04 e8 90 01 04 50 e8 90 01 04 59 2a fb 8b 45 dc 00 3c 30 90 00 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}