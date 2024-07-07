
rule Trojan_Win32_Copak_GMA_MTB{
	meta:
		description = "Trojan:Win32/Copak.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c3 44 81 c2 90 01 04 31 39 b8 b5 f8 d6 15 41 81 e8 90 01 04 48 39 f1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}