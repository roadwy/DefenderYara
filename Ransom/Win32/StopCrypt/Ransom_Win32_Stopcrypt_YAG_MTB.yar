
rule Ransom_Win32_Stopcrypt_YAG_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 ea 05 03 54 24 ?? c1 e1 04 03 4c 24 ?? 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 } //1
		$a_03_1 = {33 f5 31 74 24 ?? 8b 44 24 ?? 29 44 24 14 a1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}