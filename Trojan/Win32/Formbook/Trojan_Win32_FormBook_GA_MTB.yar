
rule Trojan_Win32_FormBook_GA_MTB{
	meta:
		description = "Trojan:Win32/FormBook.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {3d 61 12 00 00 74 90 01 01 4b c2 82 18 81 f2 bc 13 01 00 48 49 25 d7 78 01 00 f7 d2 81 eb e2 4a 01 00 c2 dd 61 35 4a fe 00 00 81 e2 09 f2 00 00 81 c1 bc 5b 01 00 81 c3 3f 74 01 00 81 e2 3a fb 00 00 81 f9 86 d9 00 00 74 90 00 } //01 00 
		$a_00_1 = {25 e8 eb 00 00 81 c1 ee d4 00 00 42 81 f1 92 63 00 00 81 f3 dd 61 01 00 81 f1 3b 23 00 00 f7 d2 c2 90 83 81 c1 90 83 01 00 81 f2 82 18 00 00 b9 2e 71 01 00 4a 05 a2 66 00 00 49 81 fb c2 b4 00 00 74 } //00 00 
	condition:
		any of ($a_*)
 
}