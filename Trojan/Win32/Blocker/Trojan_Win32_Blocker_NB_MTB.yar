
rule Trojan_Win32_Blocker_NB_MTB{
	meta:
		description = "Trojan:Win32/Blocker.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 05 8b 45 ec eb 3a 8b 0d ?? ?? ?? ?? 81 e1 00 80 00 00 85 c9 74 09 c7 45 e4 ?? ?? ?? ?? eb 07 c7 45 e4 cc 3d 43 00 } //3
		$a_01_1 = {8b 4d 0c 8b 14 81 52 e8 b2 50 00 00 83 c4 08 85 c0 74 6d } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}