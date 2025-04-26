
rule Trojan_Win32_Farfi_GNB_MTB{
	meta:
		description = "Trojan:Win32/Farfi.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 10 8b ce 83 e1 03 33 4d f8 8b 1c 8b 0f b6 4c 3e ff 33 d9 03 d8 0f b6 04 3e 33 d3 2b c2 4e 88 44 3e 01 0f b6 c0 75 b5 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}