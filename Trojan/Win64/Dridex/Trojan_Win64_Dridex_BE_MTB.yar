
rule Trojan_Win64_Dridex_BE_MTB{
	meta:
		description = "Trojan:Win64/Dridex.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 32 04 3a 8b 74 24 1c 89 74 24 6c 4c 8b 7c 24 38 43 88 04 37 4c 8b 64 24 10 4d 21 e4 49 83 c6 01 4c 89 64 24 60 4c 8b 64 24 58 4c 89 74 24 50 8b 7c 24 04 89 7c 24 44 89 54 24 48 66 8b 4c 24 6a 66 89 4c 24 6a 4d 39 e6 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}