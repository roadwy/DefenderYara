
rule Trojan_Win32_Hijacker_ARA_MTB{
	meta:
		description = "Trojan:Win32/Hijacker.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 17 80 ea 41 8a 4f 01 80 e9 41 c1 e1 04 02 d1 88 10 80 ea 17 80 f2 17 80 c2 17 88 10 40 83 c7 02 4e 75 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}