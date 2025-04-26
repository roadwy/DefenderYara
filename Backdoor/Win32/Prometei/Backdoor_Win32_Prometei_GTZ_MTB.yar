
rule Backdoor_Win32_Prometei_GTZ_MTB{
	meta:
		description = "Backdoor:Win32/Prometei.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 02 88 1c 06 88 0c 02 0f b6 1c 06 0f b6 c9 03 d9 81 e3 ?? ?? ?? ?? ?? ?? 4b 81 cb ?? ?? ?? ?? 43 8a 0c 03 8b 5d ?? 32 0c 3b 47 83 6d ?? 01 88 4f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}