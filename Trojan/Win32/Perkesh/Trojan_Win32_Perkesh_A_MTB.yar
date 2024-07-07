
rule Trojan_Win32_Perkesh_A_MTB{
	meta:
		description = "Trojan:Win32/Perkesh.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 33 8a c3 c0 e0 90 01 01 2c 1e 8b fe 02 c8 33 c0 88 0c 33 83 c9 90 01 01 43 f2 ae f7 d1 49 3b d9 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}