
rule Trojan_Win32_SmokeLoader_BD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 6c 24 04 0a ?? 83 6c 24 04 3c 8a 44 24 04 30 04 37 83 fb 0f 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}