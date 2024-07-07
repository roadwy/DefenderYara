
rule Trojan_BAT_AgentTesla_JNY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 09 17 58 0d 09 08 8e 69 32 e2 90 00 } //1
		$a_01_1 = {31 39 64 66 64 33 38 39 2d 61 31 36 35 2d 34 65 36 39 2d 62 31 61 64 2d 36 63 61 36 63 62 64 32 61 31 61 37 } //1 19dfd389-a165-4e69-b1ad-6ca6cbd2a1a7
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}