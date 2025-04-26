
rule Backdoor_Win32_Faketask_C{
	meta:
		description = "Backdoor:Win32/Faketask.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 41 43 71 49 74 79 77 47 52 31 76 33 71 47 78 56 5a 51 50 59 58 78 4d 5a 56 30 6f 32 66 7a 70 } //1 VACqItywGR1v3qGxVZQPYXxMZV0o2fzp
	condition:
		((#a_01_0  & 1)*1) >=1
 
}