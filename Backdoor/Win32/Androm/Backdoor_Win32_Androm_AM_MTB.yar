
rule Backdoor_Win32_Androm_AM_MTB{
	meta:
		description = "Backdoor:Win32/Androm.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {86 d3 96 22 62 a9 ba 3b 27 38 36 30 13 13 99 1c 04 03 20 26 26 80 80 52 d5 f9 32 44 44 7a } //1
		$a_01_1 = {27 19 21 30 13 86 ee ba ba bb 26 09 5a 21 26 ad 31 44 44 7a 04 eb 6a e3 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}