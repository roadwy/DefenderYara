
rule Trojan_Win32_Rugmi_HD_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_23_0 = {0f be 04 30 66 89 04 72 90 09 05 00 a1 90 00 00 } //6
	condition:
		((#a_23_0  & 1)*6) >=6
 
}