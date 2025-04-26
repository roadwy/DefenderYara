
rule Backdoor_Win32_SysJoker_AA_MTB{
	meta:
		description = "Backdoor:Win32/SysJoker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 11 30 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 0f b6 4c 11 ?? 30 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 0f b6 4c 11 ?? 30 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 0f b6 4c 11 ?? 30 88 ?? ?? ?? ?? 83 c0 ?? 83 f8 ?? 0f 8c } //2
		$a_01_1 = {4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 44 6b 66 4e 6c } //1 MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkfNl
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=2
 
}