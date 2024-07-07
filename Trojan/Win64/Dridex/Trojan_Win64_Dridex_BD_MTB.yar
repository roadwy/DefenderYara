
rule Trojan_Win64_Dridex_BD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8a 1c 3e 66 44 89 54 24 66 4c 8b 7c 24 28 4d 29 ff 44 30 cb 4c 89 7c 24 68 4c 8b 7c 24 50 43 88 1c 37 49 83 c6 01 4c 8b 24 24 4d 39 e6 8b 4c 24 0c 89 4c 24 18 89 54 24 1c 4c 89 74 24 20 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}