
rule Trojan_Win32_Berbew_RPY_MTB{
	meta:
		description = "Trojan:Win32/Berbew.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 45 f4 8b 00 89 45 fc 89 d9 31 d9 89 cb 83 c0 44 8b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}