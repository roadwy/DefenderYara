
rule Trojan_Win64_Rozena_HLC_MTB{
	meta:
		description = "Trojan:Win64/Rozena.HLC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 cf 5d 01 00 99 f7 7d d8 89 d0 83 c0 01 31 c3 89 d9 8b 45 ac 48 98 48 8b 55 a0 48 01 d0 89 ca 88 10 8b 45 ac 48 98 48 8b 55 a0 48 01 d0 0f b6 08 8b 45 e0 41 89 c0 8b 45 ac 48 98 48 8b 55 a0 48 01 d0 44 31 c1 89 ca 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}