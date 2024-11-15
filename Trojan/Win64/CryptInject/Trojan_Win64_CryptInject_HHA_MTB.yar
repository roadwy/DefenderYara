
rule Trojan_Win64_CryptInject_HHA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.HHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 d4 49 f7 e0 48 c1 ea 04 48 8d 0c 92 33 d2 48 c1 e1 02 4c 2b c1 49 8b c0 48 f7 f6 8a 4c 04 ?? 42 32 0c 1b 41 88 0b 4d 03 dc 41 81 fa 00 a0 05 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}