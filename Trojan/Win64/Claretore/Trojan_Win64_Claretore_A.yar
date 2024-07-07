
rule Trojan_Win64_Claretore_A{
	meta:
		description = "Trojan:Win64/Claretore.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 31 48 c1 e2 20 4c 8d 05 90 01 04 48 0b c2 ba 04 01 00 00 4c 8b c8 e8 90 00 } //1
		$a_00_1 = {24 6d 69 64 3d 25 53 26 75 69 64 3d 25 64 26 76 65 72 73 69 6f 6e 3d 25 73 24 } //1 $mid=%S&uid=%d&version=%s$
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}