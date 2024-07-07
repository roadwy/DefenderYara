
rule Backdoor_Win32_Mokes_RA_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 94 31 01 24 0a 00 88 14 30 } //2
		$a_01_1 = {33 f5 33 f7 2b de 83 6c 24 18 01 0f } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=2
 
}