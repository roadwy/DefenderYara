
rule Trojan_Win32_Qakbot_SE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 5f 54 31 47 90 01 01 8b 87 90 01 04 8b 0c 28 83 c5 90 01 01 8b 87 90 01 04 2d 90 01 04 0f af d9 31 47 90 01 01 8b 47 90 00 } //1
		$a_03_1 = {8b 47 20 2d 90 01 04 31 47 90 01 01 8b 87 90 01 04 05 90 01 04 03 c1 01 47 90 01 01 8b 87 90 01 04 88 1c 06 ff 47 90 01 01 81 fd 90 01 04 0f 8c 90 00 } //1
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}