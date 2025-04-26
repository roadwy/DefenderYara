
rule Trojan_Win64_CryptInject_MEL_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d3 49 33 d6 48 0f af d6 0f b6 45 c0 48 33 d0 48 0f af d6 0f b6 45 c1 48 33 d0 48 0f af d6 0f b6 45 c2 48 33 d0 48 0f af d6 } //2
		$a_01_1 = {31 39 38 2e 31 35 2e 38 32 2e 31 36 32 } //1 198.15.82.162
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}