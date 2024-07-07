
rule Trojan_Win32_Redline_GEQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 05 90 01 04 03 d1 81 e2 90 01 04 79 90 01 01 4a 81 ca 90 01 04 42 89 95 90 01 04 8b 95 90 01 04 0f b6 84 15 90 01 04 8b 8d 90 01 04 0f b6 91 90 01 04 33 d0 8b 85 90 01 04 88 90 00 } //10
		$a_03_1 = {5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 55 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}