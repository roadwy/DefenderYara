
rule Trojan_Win64_RokRat_A_MTB{
	meta:
		description = "Trojan:Win64/RokRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 1f 40 00 66 66 66 0f 1f 84 00 00 00 00 00 0f b6 04 11 34 fa 88 01 48 8d 49 01 49 83 e8 01 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}