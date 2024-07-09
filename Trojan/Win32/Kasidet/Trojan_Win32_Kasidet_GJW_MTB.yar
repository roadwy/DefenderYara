
rule Trojan_Win32_Kasidet_GJW_MTB{
	meta:
		description = "Trojan:Win32/Kasidet.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 c6 44 24 ?? 66 c6 44 24 ?? 65 c6 44 24 ?? 78 c6 44 24 ?? 69 c6 44 24 ?? 73 c6 44 24 ?? 74 c6 44 24 ?? 70 c6 44 24 ?? 31 c6 44 24 ?? 67 c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 6f c6 44 24 6a 6e c6 44 24 ?? 66 } //10
		$a_80_1 = {25 73 5c 66 6c 61 73 68 5f 25 73 2e 65 78 65 } //%s\flash_%s.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}