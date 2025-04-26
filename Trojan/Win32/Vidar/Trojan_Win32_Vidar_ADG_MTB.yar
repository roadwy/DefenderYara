
rule Trojan_Win32_Vidar_ADG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f c6 1c 00 00 00 00 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}