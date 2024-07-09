
rule Backdoor_BAT_AveMariaRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/AveMariaRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 0b 16 0c 2b 42 16 0d 2b 2c 07 08 09 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 d2 06 28 ?? 00 00 06 09 17 58 0d 09 17 fe 04 13 04 11 04 2d ca 06 17 58 0a 08 17 58 0c 08 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d b0 7e } //2
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}