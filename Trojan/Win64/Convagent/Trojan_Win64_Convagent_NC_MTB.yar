
rule Trojan_Win64_Convagent_NC_MTB{
	meta:
		description = "Trojan:Win64/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 32 ff 40 88 7c 24 90 01 01 e8 6f ec ff ff 8a d8 8b 0d f3 d4 02 00 83 f9 90 01 01 0f 84 1d 01 00 00 85 c9 75 4a 90 00 } //5
		$a_01_1 = {41 32 6d 61 36 41 77 } //1 A2ma6Aw
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}