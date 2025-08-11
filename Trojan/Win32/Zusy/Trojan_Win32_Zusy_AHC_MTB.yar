
rule Trojan_Win32_Zusy_AHC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 55 f4 8a 44 10 ff 8b 55 f8 8a 54 1a ff 32 c2 25 ff 00 00 00 8d 4d f0 ba 02 00 00 00 e8 } //3
		$a_03_1 = {8a 54 1f ff 0f b7 ce c1 e9 08 32 d1 88 54 18 ff 33 c0 8a 44 1f ff 66 03 f0 66 0f af 35 ?? ?? ?? 00 66 03 35 ?? ?? ?? 00 43 ff 4d f8 75 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}