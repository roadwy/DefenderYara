
rule Trojan_Win32_Copak_BH_MTB{
	meta:
		description = "Trojan:Win32/Copak.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 18 be 92 75 3c 39 81 c2 54 1f b0 10 81 c0 04 00 00 00 01 d2 39 c8 75 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}