
rule Trojan_Win32_Remcos_ARS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 07 49 68 52 05 8c 59 05 f9 36 6a f6 83 79 29 6b 35 48 69 81 35 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}