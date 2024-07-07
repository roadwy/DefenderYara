
rule PWS_Win32_Fareit_MT_MTB{
	meta:
		description = "PWS:Win32/Fareit.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c0 8a 45 90 01 01 30 45 90 01 01 89 db 89 db 8b 45 90 01 01 8a 55 90 01 01 88 10 90 09 06 00 8a 45 90 01 01 88 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}