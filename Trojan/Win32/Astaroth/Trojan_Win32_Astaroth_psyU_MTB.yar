
rule Trojan_Win32_Astaroth_psyU_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 30 40 40 00 3b c7 75 05 39 7d fc 75 0a 83 f8 02 74 05 83 f8 05 75 60 6a 04 58 6a 18 89 45 f0 89 45 f4 58 89 7d f8 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}