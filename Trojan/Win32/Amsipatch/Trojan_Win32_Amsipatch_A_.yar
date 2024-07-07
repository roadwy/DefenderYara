
rule Trojan_Win32_Amsipatch_A_{
	meta:
		description = "Trojan:Win32/Amsipatch.A!!Amsipatch.A,SIGNATURE_TYPE_ARHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 57 00 07 80 c3 90 02 90 74 90 01 01 81 90 01 01 41 4d 53 49 75 90 00 } //100
	condition:
		((#a_03_0  & 1)*100) >=100
 
}
rule Trojan_Win32_Amsipatch_A__2{
	meta:
		description = "Trojan:Win32/Amsipatch.A!!Amsipatch.A,SIGNATURE_TYPE_ARHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 57 00 07 80 c2 18 00 90 02 70 74 90 01 01 81 90 01 01 41 4d 53 49 75 90 00 } //100
	condition:
		((#a_03_0  & 1)*100) >=100
 
}