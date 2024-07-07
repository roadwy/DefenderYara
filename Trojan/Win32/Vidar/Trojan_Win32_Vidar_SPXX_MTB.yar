
rule Trojan_Win32_Vidar_SPXX_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 31 45 ec 8b 45 ec 31 45 f8 2b 75 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}