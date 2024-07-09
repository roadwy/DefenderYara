
rule Trojan_Win64_Lazy_RS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b c4 41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 05 0f be c0 6b c8 ?? 41 8a c0 2a c1 41 02 c7 41 30 01 44 03 c7 4c 03 cf 41 83 f8 ?? 7c d1 } //1
		$a_01_1 = {6b 68 78 64 6c 65 64 5c 73 61 6e 74 6f 5c 62 75 69 6c 64 5c 73 61 6e 74 6f 2e 70 64 62 } //1 khxdled\santo\build\santo.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}