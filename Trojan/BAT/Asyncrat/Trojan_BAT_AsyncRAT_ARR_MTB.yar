
rule Trojan_BAT_AsyncRAT_ARR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 0d 0a 09 05 08 12 1d 0a 1e 01 02 0c 0d 0b 0f 07 05 1e 00 14 1e 00 01 00 00 1e 01 1e 01 09 06 } //12
		$a_01_1 = {09 04 0a 02 05 08 13 07 05 14 1e 00 01 00 00 14 1e 00 01 00 00 1e 01 1e 00 09 0d 07 04 14 1e 00 } //8
	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}
rule Trojan_BAT_AsyncRAT_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 0a 20 00 15 12 80 99 01 12 80 9d 0a 20 00 15 12 80 99 01 12 80 a5 0d 20 01 15 12 80 a9 01 12 80 85 12 80 b1 05 20 00 11 80 b5 05 20 00 12 80 bd 08 20 00 15 12 80 a9 01 0e 05 20 00 12 80 c5 05 20 00 12 80 c9 09 20 02 01 12 80 c9 12 80 c9 0e 07 08 08 1d 0e 0e 0e 11 71 12 5d 12 5d 09 06 00 01 11 80 dd 0d 06 0a 02 11 71 11 64 03 12 82 d9 06 20 01 01 11 } //30
	condition:
		((#a_01_0  & 1)*30) >=30
 
}