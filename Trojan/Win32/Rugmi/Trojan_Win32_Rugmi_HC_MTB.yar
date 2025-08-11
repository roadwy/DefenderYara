
rule Trojan_Win32_Rugmi_HC_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_23_0 = {0f be 04 08 66 89 04 4e 41 a1 90 09 05 00 a1 90 01 04 66 0f be 04 08 66 89 04 4e 41 a1 90 1b 01 90 00 00 } //1
	condition:
		((#a_23_0  & 1)*1) >=1
 
}