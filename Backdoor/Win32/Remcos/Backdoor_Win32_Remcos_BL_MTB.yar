
rule Backdoor_Win32_Remcos_BL_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 07 0b d0 88 95 [0-04] 0f b6 8d [0-04] f7 d9 88 8d [0-04] 8b 95 [0-04] 8a 85 [0-04] 88 84 15 [0-04] e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}