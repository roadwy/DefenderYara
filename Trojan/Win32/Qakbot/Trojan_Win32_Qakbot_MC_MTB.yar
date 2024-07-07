
rule Trojan_Win32_Qakbot_MC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d 90 01 04 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 8b 45 f8 83 c0 04 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af da 8d 50 ff 33 d0 89 91 fc 00 00 00 8b 81 00 01 00 00 01 41 50 8b 81 ec 00 00 00 01 41 10 8b 81 80 00 00 00 8b 91 a8 00 00 00 88 1c 02 ff 81 80 00 00 00 8b 81 c0 00 00 00 2b 81 0c 01 00 00 35 90 01 04 01 81 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Qakbot_MC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 6a 61 75 7a 79 4f } //1 OjauzyO
		$a_01_1 = {57 44 67 76 51 49 39 34 37 50 4e 37 } //1 WDgvQI947PN7
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_3 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_4 = {6e 64 75 6b 74 70 65 37 30 39 62 66 35 35 2e 64 6c 6c } //1 nduktpe709bf55.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}