
rule Trojan_Win32_Swisyn_ASW_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 55 51 55 e8 ?? ?? ?? ?? 85 c0 75 0f 6a 10 68 ac ?? ba 00 68 3c ?? ba 00 55 ff d7 6a ff 8d 54 24 20 55 52 6a 02 ff d6 3b c5 } //3
		$a_03_1 = {8d 44 24 00 68 ec ?? ba 00 50 e8 ?? ?? ?? ?? 83 c4 08 8d 4c 24 00 6a 10 68 ac ?? ba 00 51 6a 00 ff 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Swisyn_ASW_MTB_2{
	meta:
		description = "Trojan:Win32/Swisyn.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 56 68 20 f7 e1 00 56 56 50 8b 44 24 2c 6a 01 6a 03 68 10 01 00 00 68 ff 01 0f 00 50 50 57 ff 15 ?? ?? ?? ?? 8b 1d 04 60 e1 00 8b f0 85 f6 74 25 8b 4c 24 1c 8b 54 24 18 51 52 56 } //2
		$a_03_1 = {8d 53 41 8d 44 24 14 52 68 5c b1 e1 00 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 4c 24 14 51 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}