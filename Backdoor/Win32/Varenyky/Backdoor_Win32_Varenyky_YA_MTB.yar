
rule Backdoor_Win32_Varenyky_YA_MTB{
	meta:
		description = "Backdoor:Win32/Varenyky.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d2 89 c1 89 d8 f7 f1 89 f0 83 c3 01 83 ec 04 32 90 01 05 88 90 01 05 81 90 01 05 75 90 01 01 c7 90 01 06 31 ed e8 90 01 04 c7 90 01 06 89 c7 89 90 01 03 e8 90 01 04 83 ec 04 c7 90 01 07 89 90 01 02 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}