
rule TrojanDropper_AndroidOS_SAgent_KA_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.KA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4b ac 20 1c 00 21 0c 22 02 f0 ?? ?? 01 9b 08 22 99 19 20 1c 02 f0 ?? ?? 20 1c 02 f0 ?? ?? 58 af 05 1c 00 21 31 22 38 1c 02 f0 ?? ?? 31 1c 01 9b 0a ac 08 31 59 18 20 1c 3a 1c 30 23 ff f7 ?? ?? 38 36 28 1c 07 96 02 f0 ?? ?? 06 1c 01 9b 07 9a 20 1c 99 18 2b 1c 32 1c } //1
		$a_03_1 = {80 22 e5 ac 52 00 20 1c 00 21 02 f0 ?? ?? 20 1c 09 99 02 f0 ?? ?? 20 1c a5 a9 02 f0 ?? ?? ?? ?? 20 1c 79 44 02 f0 ?? ?? 20 1c ff f7 ?? ?? ?? ?? 20 1c 79 44 02 f0 ?? ?? 20 1c ff f7 ?? ?? ?? ?? 21 1c 78 44 2c 30 02 f0 ?? ?? 20 1c 39 1c 02 f0 ?? ?? ?? ?? 20 1c 79 44 02 f0 ?? ?? 04 1c 01 22 23 1c 29 1c 30 1c 02 f0 ?? ?? 20 1c 02 f0 ?? ?? 20 1c 02 f0 ?? ?? 30 1c 02 f0 ?? ?? 07 9b 06 9a 5e 19 05 9b 01 33 05 93 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}