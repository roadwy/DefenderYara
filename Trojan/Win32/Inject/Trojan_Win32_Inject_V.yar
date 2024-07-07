
rule Trojan_Win32_Inject_V{
	meta:
		description = "Trojan:Win32/Inject.V,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff e0 90 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a } //1
		$a_03_1 = {30 03 43 81 fb 9c 59 00 01 75 90 03 01 01 f2 f3 e8 90 01 02 ff ff eb 0a 90 00 } //1
		$a_03_2 = {8b 00 8b f0 85 f6 7e 1c bb 01 00 00 00 8b c5 e8 90 01 02 ff ff 0f b6 14 24 32 54 1f ff 88 54 18 ff 43 4e 75 e9 5a 5d 5f 5e 5b c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}