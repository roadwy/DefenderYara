
rule Trojan_BAT_AgentTesla_MAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 02 16 2a 16 0a 16 0b 28 ?? ?? ?? 0a 0c 16 0d 2b 4b 08 09 9a 6f ?? ?? ?? 0a 03 28 ?? ?? ?? 0a 2c 37 06 2d 15 08 09 9a } //5
		$a_01_1 = {62 39 64 39 38 30 33 34 2d 34 35 36 63 2d 34 66 39 37 2d 39 35 64 61 2d 62 33 65 31 39 32 61 65 34 62 66 36 } //1 b9d98034-456c-4f97-95da-b3e192ae4bf6
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}