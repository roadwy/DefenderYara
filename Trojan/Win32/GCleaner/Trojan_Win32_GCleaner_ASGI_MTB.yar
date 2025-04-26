
rule Trojan_Win32_GCleaner_ASGI_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 14 38 83 fb 0f 75 } //5
		$a_03_1 = {ff d7 c7 05 ?? ?? ?? 00 98 ac 58 ec 89 1d ?? ?? ?? 00 46 81 fe } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}