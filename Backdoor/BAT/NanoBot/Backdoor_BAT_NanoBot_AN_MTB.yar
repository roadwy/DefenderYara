
rule Backdoor_BAT_NanoBot_AN_MTB{
	meta:
		description = "Backdoor:BAT/NanoBot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 1f 00 00 70 28 01 00 00 06 00 2a } //2
		$a_03_1 = {07 16 6f 05 ?? ?? 0a 00 07 17 6f 06 ?? ?? 0a 90 0a 1c 00 73 03 ?? ?? 0a 0a 06 73 04 ?? ?? 0a 0b } //2
		$a_01_2 = {45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 41 73 41 64 6d 69 6e } //1 ExecuteCommandAsAdmin
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}