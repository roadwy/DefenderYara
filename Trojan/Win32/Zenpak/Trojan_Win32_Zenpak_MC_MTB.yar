
rule Trojan_Win32_Zenpak_MC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 eb 90 01 01 89 2d 70 e0 56 00 58 a3 6c e0 56 00 ba 04 00 00 00 01 15 70 e0 56 00 66 6a 0a 50 e8 90 01 04 89 d9 89 0d 68 e0 56 00 89 f1 89 0d 60 e0 56 00 89 3d 64 e0 56 00 eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}