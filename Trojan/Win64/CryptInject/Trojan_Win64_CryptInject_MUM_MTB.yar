
rule Trojan_Win64_CryptInject_MUM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 d4 48 f7 e1 48 c1 ea 03 48 6b c2 ?? 48 2b c8 48 03 ce 8a 44 0c 20 42 32 04 1b 41 88 03 4d 03 dc 41 81 fa 00 5a 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}