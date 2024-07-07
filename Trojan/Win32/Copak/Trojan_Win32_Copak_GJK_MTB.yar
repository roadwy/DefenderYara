
rule Trojan_Win32_Copak_GJK_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e9 82 f9 e9 71 31 10 b9 ac b2 04 24 40 46 39 f8 75 90 01 01 21 c9 c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}