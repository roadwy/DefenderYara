
rule Trojan_Win32_Midie_AMX_MTB{
	meta:
		description = "Trojan:Win32/Midie.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 17 58 50 89 c0 35 85 00 00 00 90 80 07 63 80 2f 27 58 50 89 c0 35 85 00 00 00 90 f6 2f 47 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}