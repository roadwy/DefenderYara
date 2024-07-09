
rule Trojan_Win64_CryptInject_GMT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8d 47 01 43 32 94 3e e8 03 00 00 88 54 2b 10 83 e0 0f 48 83 c5 ?? 49 89 c7 4c 39 e5 0f 8d f3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}