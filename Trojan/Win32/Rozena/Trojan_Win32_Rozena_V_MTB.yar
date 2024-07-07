
rule Trojan_Win32_Rozena_V_MTB{
	meta:
		description = "Trojan:Win32/Rozena.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 89 95 90 01 04 8b 85 90 01 04 35 90 01 04 89 85 90 09 06 00 8b 95 90 00 } //1
		$a_03_1 = {2b d1 89 95 90 01 04 8b 85 90 01 04 05 90 01 04 89 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}