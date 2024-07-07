
rule Virus_Win32_Mammer_A{
	meta:
		description = "Virus:Win32/Mammer.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d b1 6b 8b fe 51 ad 92 ad 91 56 57 6a 20 5e b8 20 37 ef c6 ff d5 e8 24 00 00 00 2b cf 52 8b d1 ff d5 5a 2d b9 79 37 9e 8b d8 e8 15 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}