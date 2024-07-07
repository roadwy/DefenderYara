
rule Backdoor_Win32_Coroxy_FT_MTB{
	meta:
		description = "Backdoor:Win32/Coroxy.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 89 45 90 01 01 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 33 c0 89 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 83 e8 90 01 01 89 45 90 01 01 c7 45 90 01 05 c7 45 90 01 05 33 c0 89 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}