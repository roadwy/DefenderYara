
rule Trojan_Win32_Vidar_AD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 80 f2 ff 41 20 f2 41 88 fb 41 80 f3 ff 40 88 de 44 20 de 80 f3 ff 40 20 df 40 08 fe 45 88 d3 41 20 f3 41 30 f2 45 08 d3 41 f6 c3 01 b8 37 89 da 81 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}