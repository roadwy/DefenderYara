
rule Backdoor_Win32_Crypminal_AR_MTB{
	meta:
		description = "Backdoor:Win32/Crypminal.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c0 40 3d 37 d0 55 04 75 f8 33 c0 69 d0 4e 09 00 00 40 3d 37 d0 55 04 75 f2 } //00 00 
	condition:
		any of ($a_*)
 
}