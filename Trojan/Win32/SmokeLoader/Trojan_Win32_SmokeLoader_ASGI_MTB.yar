
rule Trojan_Win32_SmokeLoader_ASGI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c3 30 08 83 7d 0c 0f 75 } //5
		$a_01_1 = {8b 4d fc 5f 5e 33 cd 5b e8 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}