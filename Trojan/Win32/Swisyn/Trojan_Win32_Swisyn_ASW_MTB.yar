
rule Trojan_Win32_Swisyn_ASW_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 56 68 20 f7 e1 00 56 56 50 8b 44 24 2c 6a 01 6a 03 68 10 01 00 00 68 ff 01 0f 00 50 50 57 ff 15 ?? ?? ?? ?? 8b 1d 04 60 e1 00 8b f0 85 f6 74 25 8b 4c 24 1c 8b 54 24 18 51 52 56 } //2
		$a_03_1 = {8d 53 41 8d 44 24 14 52 68 5c b1 e1 00 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 4c 24 14 51 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}