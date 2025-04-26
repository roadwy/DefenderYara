
rule Trojan_Win32_Bingo_AJ_MTB{
	meta:
		description = "Trojan:Win32/Bingo.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a c1 02 c2 30 44 0d f5 41 83 f9 05 73 05 8a 55 f4 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}