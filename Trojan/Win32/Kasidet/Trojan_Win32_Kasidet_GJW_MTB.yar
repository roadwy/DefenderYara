
rule Trojan_Win32_Kasidet_GJW_MTB{
	meta:
		description = "Trojan:Win32/Kasidet.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 c6 44 24 90 01 01 66 c6 44 24 90 01 01 65 c6 44 24 90 01 01 78 c6 44 24 90 01 01 69 c6 44 24 90 01 01 73 c6 44 24 90 01 01 74 c6 44 24 90 01 01 70 c6 44 24 90 01 01 31 c6 44 24 90 01 01 67 c6 44 24 90 01 01 6f c6 44 24 90 01 01 74 c6 44 24 90 01 01 6f c6 44 24 6a 6e c6 44 24 90 01 01 66 90 00 } //10
		$a_80_1 = {25 73 5c 66 6c 61 73 68 5f 25 73 2e 65 78 65 } //%s\flash_%s.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}