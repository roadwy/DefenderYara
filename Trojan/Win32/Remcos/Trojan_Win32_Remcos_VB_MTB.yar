
rule Trojan_Win32_Remcos_VB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.VB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 02 00 cc d2 02 00 da d2 02 00 e8 d2 02 00 fa d2 02 00 08 d3 02 00 1c d3 02 00 32 d3 02 00 3c d3 02 00 58 d3 02 00 6e d3 02 00 7c d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}