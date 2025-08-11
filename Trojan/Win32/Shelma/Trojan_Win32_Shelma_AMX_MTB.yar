
rule Trojan_Win32_Shelma_AMX_MTB{
	meta:
		description = "Trojan:Win32/Shelma.AMX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 85 c0 74 39 66 3b 02 74 29 66 83 f8 61 72 06 66 83 f8 7a 76 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}