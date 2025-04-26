
rule Trojan_Win32_FormBook_DM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.DM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 81 f9 1a 65 00 00 74 10 59 40 2d 1e 26 01 00 81 c2 2e 71 01 00 49 40 58 58 b8 41 0c 00 00 81 ea c7 2d 01 00 f7 d0 c2 56 88 59 81 c2 b3 69 00 00 81 e3 a2 66 00 00 bb f3 05 01 00 f7 d3 3d 6b 04 01 00 74 14 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}