
rule Virus_Win32_Lamechi{
	meta:
		description = "Virus:Win32/Lamechi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 2d 00 00 00 87 06 03 f2 03 fa e2 f0 68 6f 6e 00 00 68 75 72 6c 6d 54 ff 55 fc 59 59 ff 37 50 e8 0d 00 00 00 87 06 61 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}