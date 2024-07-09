
rule Backdoor_Win32_Lotok_GNR_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca 0f af c8 8a 44 24 ?? 23 d1 32 c3 89 15 ?? ?? ?? ?? 8b 54 24 ?? 2a c3 32 c3 89 0d ?? ?? ?? ?? 02 c3 83 c4 ?? 88 04 2a 45 84 c0 ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 83 c6 ?? 03 c6 3b c1 0f 8c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}