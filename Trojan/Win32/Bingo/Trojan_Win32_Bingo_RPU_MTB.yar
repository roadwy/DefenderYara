
rule Trojan_Win32_Bingo_RPU_MTB{
	meta:
		description = "Trojan:Win32/Bingo.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 55 0c 33 c0 85 d2 74 1a 56 8b 75 10 57 8b 7d 08 8b c8 83 e1 03 8a 0c 31 30 0c 38 40 3b c2 72 f0 5f 5e 33 c0 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}