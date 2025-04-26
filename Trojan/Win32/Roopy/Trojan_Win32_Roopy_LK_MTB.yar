
rule Trojan_Win32_Roopy_LK_MTB{
	meta:
		description = "Trojan:Win32/Roopy.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 31 4f 81 c1 04 00 00 00 39 c1 75 ee 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}