
rule Trojan_Win32_Farfi_GPA_MTB{
	meta:
		description = "Trojan:Win32/Farfi.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 75 10 b8 cd cc cc cc 80 c2 36 30 11 f7 65 0c 8b 4d 08 8b 45 0c 41 c1 ea 03 40 c7 45 08 00 00 00 00 89 45 0c 8d 14 92 03 d2 3b fa 8b 55 08 0f 45 d1 89 55 08 3b c3 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}