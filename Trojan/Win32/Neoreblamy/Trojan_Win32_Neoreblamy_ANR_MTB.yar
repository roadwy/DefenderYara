
rule Trojan_Win32_Neoreblamy_ANR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ANR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 9d c1 81 f9 ed 1a 10 88 1b c9 33 d2 41 3b c1 0f 9f c2 69 45 d4 f9 47 00 00 33 c9 3b d0 0f 9e c1 81 e9 02 fc 00 00 f7 d9 1b c9 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}