
rule Trojan_Win32_Eqtonex_RPF_MTB{
	meta:
		description = "Trojan:Win32/Eqtonex.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ec 08 85 c0 75 15 8b 44 24 18 8b 54 24 14 0f b7 04 58 8b 0c 82 01 e9 89 4c 24 10 83 c3 01 39 5f 18 77 c7 } //1
		$a_01_1 = {89 c2 89 c5 c1 ea 1c c1 ed 1e 83 e5 01 83 e2 02 01 ea 89 c5 c1 ed 1f 8d 54 55 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}