
rule Trojan_Win32_Cobalt_GPA_MTB{
	meta:
		description = "Trojan:Win32/Cobalt.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f1 05 80 e9 04 80 f1 03 80 e9 03 88 8c 05 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}