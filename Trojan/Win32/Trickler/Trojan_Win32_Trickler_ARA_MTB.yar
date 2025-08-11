
rule Trojan_Win32_Trickler_ARA_MTB{
	meta:
		description = "Trojan:Win32/Trickler.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 8a 4c 95 42 00 8a c1 24 80 d0 e1 3a c3 74 03 80 c9 01 8a 82 4d 95 42 00 32 c1 8a c8 80 e1 01 d0 e8 3a cb 74 02 0c 80 88 82 4c 95 42 00 42 83 fa 03 7c cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}