
rule Trojan_Win64_Cobeacon_MBWJ_MTB{
	meta:
		description = "Trojan:Win64/Cobeacon.MBWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 72 64 61 74 61 00 00 44 4a 01 00 00 c0 03 00 00 4c 01 00 00 b0 03 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 60 04 00 00 00 10 05 00 00 02 00 00 00 fc 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
		$a_01_1 = {65 78 74 00 00 00 37 aa 03 00 00 10 00 00 00 ac 03 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}