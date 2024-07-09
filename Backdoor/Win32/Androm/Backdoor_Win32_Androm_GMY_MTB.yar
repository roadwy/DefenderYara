
rule Backdoor_Win32_Androm_GMY_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 24 8b d8 52 ff 15 ?? ?? ?? ?? 8b e8 8b 44 24 28 50 66 c7 44 24 ?? 02 00 ff d3 66 89 44 24 12 8b 4d 0c 68 ?? ?? ?? ?? 8b 11 8b 0d ?? ?? ?? ?? 51 8b 02 89 44 24 1c ff d6 8b 4f 08 8d 54 24 10 6a 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}