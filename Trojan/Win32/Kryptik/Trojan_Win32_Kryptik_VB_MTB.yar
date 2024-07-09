
rule Trojan_Win32_Kryptik_VB_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 12 ba 82 b4 3d 49 8a e8 d5 38 c1 fa 02 79 } //1
		$a_03_1 = {42 6e 00 a8 89 c0 04 d8 d3 bf 04 30 89 c0 04 28 6e 74 ?? b8 88 c0 04 d0 7a ?? 00 40 88 c0 04 88 6f b6 04 c8 87 c0 04 b8 80 b6 04 50 87 c0 04 30 9a ?? ?? ?? ?? ?? ?? e0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}