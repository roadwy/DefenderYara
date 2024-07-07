
rule Trojan_Win32_MixLoader_RJ_MTB{
	meta:
		description = "Trojan:Win32/MixLoader.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 14 50 ff 15 60 e2 46 00 ff 15 64 e2 46 00 e9 } //1
		$a_01_1 = {83 6a 0c 01 8b 42 00 74 2c 85 c0 89 4a 08 8a 40 01 89 41 fc 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}