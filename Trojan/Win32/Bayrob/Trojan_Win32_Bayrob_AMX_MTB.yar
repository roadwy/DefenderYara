
rule Trojan_Win32_Bayrob_AMX_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.AMX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 e8 76 17 00 00 59 e8 d0 06 00 00 0f b7 c0 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}