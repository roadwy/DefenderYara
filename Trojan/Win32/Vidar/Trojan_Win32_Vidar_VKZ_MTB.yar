
rule Trojan_Win32_Vidar_VKZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 00 85 c0 75 4a 8b b4 24 30 0c 00 00 89 f1 68 09 ae 41 00 8d 5c 24 14 53 e8 6c f5 ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}