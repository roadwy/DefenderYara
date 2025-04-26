
rule Backdoor_BAT_NanoCoreRAT_C_MTB{
	meta:
		description = "Backdoor:BAT/NanoCoreRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 1a } //2
		$a_01_1 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}