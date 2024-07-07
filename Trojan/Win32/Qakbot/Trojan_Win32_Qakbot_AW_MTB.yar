
rule Trojan_Win32_Qakbot_AW_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 f7 7d ec 8b 45 10 0f b6 14 10 03 ca 88 4d ff 0f b6 45 ff 8b 4d 08 03 4d f8 0f b6 11 33 d0 8b 45 08 03 45 f8 88 10 0f b6 4d f0 8b 45 f8 99 f7 7d ec 8b 45 10 0f b6 14 10 2b ca 88 4d ff e9 } //4
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}