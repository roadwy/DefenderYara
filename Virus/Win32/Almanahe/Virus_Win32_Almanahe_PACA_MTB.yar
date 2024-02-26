
rule Virus_Win32_Almanahe_PACA_MTB{
	meta:
		description = "Virus:Win32/Almanahe.PACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {37 47 b7 80 c5 82 90 01 04 b9 2c cd a1 08 2c 7c 44 44 44 43 63 c0 0d d1 01 05 83 bc a0 7f 99 56 90 00 } //01 00 
		$a_01_1 = {b9 9e 04 00 00 80 04 19 a2 e2 fa } //00 00 
	condition:
		any of ($a_*)
 
}