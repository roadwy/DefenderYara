
rule Virus_Win32_Zero_RS_MTB{
	meta:
		description = "Virus:Win32/Zero.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 c0 01 01 00 00 0f b6 c9 03 c1 c1 e1 10 8d 76 01 33 c1 8a 0e 84 c9 75 e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}