
rule Worm_Win32_Gamarue_U{
	meta:
		description = "Worm:Win32/Gamarue.U,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f0 4e 39 0d 40 30 00 10 76 14 8a 14 0e 32 d0 80 c2 42 88 14 0e 41 3b 0d 40 30 00 10 72 ec ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}