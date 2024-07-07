
rule Backdoor_Win32_Shark_F{
	meta:
		description = "Backdoor:Win32/Shark.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e 00 65 00 78 00 65 00 90 02 10 7c 00 7c 00 7c 00 90 02 10 74 00 65 00 6d 00 70 00 90 02 18 2e 00 65 00 78 00 65 00 90 02 10 70 00 34 00 35 00 35 00 77 00 30 00 72 00 64 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}