
rule PWS_Win32_Fareit_AM{
	meta:
		description = "PWS:Win32/Fareit.AM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {54 6a 40 68 78 59 00 00 57 e8 aa 2e fa ff [0-04] 33 d2 33 c0 89 04 24 b8 [0-05] 8b f7 03 f2 [0-03] 8a 08 [0-03] 80 f1 4e [0-03] 88 0e [0-0d] ff 04 24 40 81 3c 24 79 59 00 00 75 d5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}