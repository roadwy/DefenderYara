
rule Trojan_Win32_Hanictor_VAM_MTB{
	meta:
		description = "Trojan:Win32/Hanictor.VAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 75 0c 83 ee 25 33 35 90 01 04 81 ee aa 17 67 f3 03 75 14 83 f6 7a 81 ee 0a b3 03 68 89 75 f8 bf 30 00 00 00 89 7d 14 90 00 } //1
		$a_01_1 = {33 7d 14 83 ef 6f 33 7d 0c 2b fe 83 c7 5c 81 f7 a0 ef 8b ce 89 7d fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}