
rule Backdoor_Win32_Remcos_PS_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6e 03 0f 66 a9 fd 0e 66 a4 35 00 66 0f 98 10 66 90 01 01 0d 0e 66 2f 4e 0e 66 b9 22 0d 66 d7 a3 00 66 f6 6d 10 66 90 01 01 92 0f 66 30 6c 0e 66 ed ee 0e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}