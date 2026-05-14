
rule Backdoor_Win64_ReverseShell_MK_MTB{
	meta:
		description = "Backdoor:Win64/ReverseShell.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 63 6d 64 2e 65 78 65 00 ba 00 00 00 00 48 89 45 d0 48 89 55 d8 48 8d 55 e0 b8 00 00 00 00 b9 1d 00 00 00 48 89 d7 f3 48 ab 48 89 fa 89 02 48 83 c2 04 66 89 02 48 83 c2 02 88 02 48 83 c2 01 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}