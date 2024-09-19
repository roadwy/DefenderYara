
rule Trojan_Win32_Farfli_ASGH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 8a 08 30 0a 90 55 8b ec 41 49 83 c4 04 83 c4 fc 90 90 8b e5 90 5d 8a 08 00 0a 55 90 8b ec 85 f6 56 5e 83 c4 06 83 c4 fa 90 90 8b e5 90 5d 42 40 4f 75 92 } //2
		$a_01_1 = {50 88 55 c3 c6 45 b4 72 c6 45 b5 75 c6 45 b6 6e c6 45 b7 64 c6 45 b8 6c c6 45 b9 6c c6 45 ba 33 c6 45 bb 32 c6 45 bc 2e 88 5d bd c6 45 be 78 88 5d bf 51 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}