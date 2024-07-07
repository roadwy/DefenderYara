
rule Trojan_Win32_Strab_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Strab.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ef 8a 86 90 01 04 c0 c0 90 01 01 32 81 90 01 04 88 86 90 01 04 89 d0 c1 e8 90 01 01 c1 fa 90 01 01 01 c2 8d 04 52 8d 04 82 f7 d8 01 c1 41 46 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}