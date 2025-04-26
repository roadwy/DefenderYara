
rule Trojan_Win32_Fauppod_MM_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {eb 6a d8 d2 d8 e6 d8 df d8 d0 d8 c9 d8 cc d8 c1 89 0a d8 e8 d8 c4 d8 d7 d8 c0 d8 ed d8 d8 d8 c2 d8 e8 d8 c2 d8 cb 88 13 d8 cc d8 e8 d8 e9 d8 c5 d8 d6 d8 ed d8 e6 d8 d7 d8 e7 8a 0d d8 c1 d8 c0 } //5
		$a_01_1 = {d8 ce d8 c6 d8 e2 d8 d0 d8 ed d8 ed d8 c4 88 0a d8 df d8 dd d8 c6 d8 cd 88 0d d8 e5 d8 e1 d8 c3 d8 e3 d8 d7 d8 d6 d8 d9 d8 d8 89 0e e9 84 } //5
		$a_01_2 = {e9 8a 00 00 00 d8 de d8 dd d8 e8 d8 c5 d8 e7 d8 e4 d8 c6 d8 cb 88 0b d8 c5 d8 c5 d8 e4 d8 e4 d8 c6 d8 c4 89 0f d8 d5 d8 c0 d8 cc d8 cc d8 c2 d8 e3 d8 c7 d8 cd 89 0b d8 cf d8 d0 d8 d2 d8 d1 d8 } //5
		$a_01_3 = {e0 d8 c7 d8 c3 d8 ed d8 d0 d8 d6 89 0c d8 e0 d8 da d8 ce d8 d8 d8 c6 d8 cb d8 cf d8 df d8 e0 d8 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=10
 
}