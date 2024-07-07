
rule Trojan_Win32_Zenpak_GMU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 83 f2 07 42 01 d0 eb 30 83 f0 04 42 01 2d 90 01 04 48 83 c0 08 01 3d 90 01 04 48 8d 05 90 01 04 31 18 83 e8 04 01 d0 8d 05 90 01 04 31 30 e9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}