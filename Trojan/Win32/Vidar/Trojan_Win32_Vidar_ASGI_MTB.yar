
rule Trojan_Win32_Vidar_ASGI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 ?? ?? ?? ff 2b d8 8b 45 ?? 31 18 6a 00 e8 } //4
		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}