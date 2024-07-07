
rule Trojan_Win32_Vidar_UMP_MTB{
	meta:
		description = "Trojan:Win32/Vidar.UMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c6 0f b6 c0 8a 44 04 2c 30 04 3b 85 ed 74 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}