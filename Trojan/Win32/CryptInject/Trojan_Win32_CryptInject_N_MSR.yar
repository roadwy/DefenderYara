
rule Trojan_Win32_CryptInject_N_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.N!MSR,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 6a 00 89 3c 24 33 ff 03 fb 8b c7 5f aa 49 75 c4 } //1
		$a_01_1 = {2b 14 24 03 55 f8 83 e0 00 03 c2 5a 0f b6 1c 30 57 33 3c 24 03 7d f0 83 e2 00 0b d7 5f d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d f4 75 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}