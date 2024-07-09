
rule TrojanDropper_Win32_Cutwail_H{
	meta:
		description = "TrojanDropper:Win32/Cutwail.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 ?? ?? 40 00 8b 45 08 [0-03] (8d 8e b0 00 00 00 89 01|89 86 b0 00 00 00) 56 } //1
		$a_02_1 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc 8d 05 ?? ?? 40 00 50 6a 00 e8 ?? ?? ff ff ff 15 ?? ?? 40 00 8b 45 0c 8d 0e 81 c1 b0 00 00 00 89 01 56 } //1
		$a_02_2 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 ?? ?? 40 00 8b 45 0c 8d 0e 81 c1 b0 00 00 00 89 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}