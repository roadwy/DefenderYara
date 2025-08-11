
rule Trojan_Win64_Helcobtik_A{
	meta:
		description = "Trojan:Win64/Helcobtik.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 a9 74 64 cf [0-10] c1 ea 06 6b c2 4f } //1
		$a_03_1 = {b8 a9 74 64 cf [0-10] 66 83 e1 7f 66 89 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}