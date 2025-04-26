
rule Backdoor_Win32_Hupigon_CY{
	meta:
		description = "Backdoor:Win32/Hupigon.CY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff ff ff 0c 00 00 00 20 67 6f 74 6f 20 52 65 70 65 61 74 90 05 04 01 00 ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00 } //1
		$a_01_1 = {8d 45 e8 50 8d 45 ea 50 68 2a 54 00 00 8d 85 ba ab ff ff 50 6a 32 6a 00 ff 15 } //1
		$a_03_2 = {50 6a 00 e8 ?? ?? ?? ?? 80 7b 50 00 74 23 0f b7 05 ?? ?? ?? ?? 50 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 33 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}