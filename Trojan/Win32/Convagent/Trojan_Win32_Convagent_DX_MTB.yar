
rule Trojan_Win32_Convagent_DX_MTB{
	meta:
		description = "Trojan:Win32/Convagent.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {50 8d 45 fc 50 8b 45 fc 8d 04 86 50 56 57 e8 [0-04] 8b 45 fc 83 c4 14 48 89 35 a8 bc 45 01 5f 5e a3 a4 bc 45 01 5b c9 } //3
		$a_01_1 = {53 00 74 00 65 00 61 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //1 SteamService.exe
		$a_01_2 = {2e 69 38 31 34 } //1 .i814
		$a_01_3 = {2e 69 38 31 35 } //1 .i815
		$a_01_4 = {2e 69 38 31 36 } //1 .i816
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}