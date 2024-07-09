
rule Backdoor_Win32_Androm_GMX_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f0 8b 44 24 ?? 50 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 8b f8 51 66 c7 44 24 ?? 02 00 ff d6 66 89 44 24 ?? 8b 57 ?? 68 ?? ?? ?? ?? 53 8b 02 8b 08 89 4c 24 ?? ff d5 8b 74 24 ?? 8d 54 24 ?? 6a 10 52 8b 4e ?? 51 ff d0 83 f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}