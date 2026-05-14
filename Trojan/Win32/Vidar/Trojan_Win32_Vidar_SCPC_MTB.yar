
rule Trojan_Win32_Vidar_SCPC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SCPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 20 20 20 20 b0 00 00 00 00 b0 02 00 00 02 00 00 00 fe 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 72 73 72 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}