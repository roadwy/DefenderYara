
rule Trojan_Win32_Neoreblamy_ANEO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ANEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 b9 6b c6 45 ba b7 c6 45 bb c3 c6 45 bc 36 c6 45 bd 12 c6 45 be b7 c6 45 bf d9 c6 45 c0 45 c6 45 c1 2e c6 45 c2 e0 c6 45 c3 f6 c6 45 c4 89 c6 45 c5 7c c6 45 c6 55 c6 45 c7 db c6 45 c8 ee c6 45 c9 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}