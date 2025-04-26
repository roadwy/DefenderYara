
rule Trojan_Win32_CryptInject_TBM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.TBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b fe 88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 97 c6 44 24 44 74 88 54 24 46 c6 44 24 40 95 c6 44 24 39 62 c7 44 24 10 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}