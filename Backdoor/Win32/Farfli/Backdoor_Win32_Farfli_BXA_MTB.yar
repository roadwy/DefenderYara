
rule Backdoor_Win32_Farfli_BXA_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {a0 78 5b 04 42 31 29 32 d0 40 81 ca 90 01 04 32 9a 90 01 04 30 5f 32 c6 4d 55 30 73 a5 97 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}