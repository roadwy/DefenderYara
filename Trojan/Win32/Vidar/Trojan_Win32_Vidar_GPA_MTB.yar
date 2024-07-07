
rule Trojan_Win32_Vidar_GPA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 02 32 04 31 88 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}