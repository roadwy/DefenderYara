
rule Backdoor_Win32_Venik_CnC{
	meta:
		description = "Backdoor:Win32/Venik!CnC,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 16 00 00 20 0f 87 07 01 00 00 0f 84 cc 00 00 00 3d 12 00 00 20 77 7d 74 65 3d 06 00 00 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=100
 
}