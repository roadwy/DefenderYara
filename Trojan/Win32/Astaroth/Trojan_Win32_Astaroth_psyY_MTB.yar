
rule Trojan_Win32_Astaroth_psyY_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 ec 5c 02 00 00 56 57 6a 11 33 c0 59 8d 7d ac f3 ab 8d 7d f0 c7 45 ac 44 00 00 00 ab } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}