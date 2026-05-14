
rule Trojan_Win32_Lobshot_ALB_MTB{
	meta:
		description = "Trojan:Win32/Lobshot.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 57 c7 44 24 14 57 54 53 45 c7 44 24 18 6e 75 6d 65 c7 44 24 1c 72 61 74 65 c7 44 24 20 53 65 73 73 c7 44 24 24 69 6f 6e 73 c7 44 24 28 41 00 00 00 ff d6 8d 44 24 0c c7 44 24 0c 57 54 53 51 50 57 c7 44 24 18 75 65 72 79 c7 44 24 1c 55 73 65 72 c7 44 24 20 54 6f 6b 65 c7 44 24 24 6e 00 00 00 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}