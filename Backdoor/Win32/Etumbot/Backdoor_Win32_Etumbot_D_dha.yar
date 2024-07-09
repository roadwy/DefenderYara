
rule Backdoor_Win32_Etumbot_D_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f4 61 70 70 64 c7 45 f8 61 74 61 00 c7 85 ?? f9 ff ff 5c 76 65 63 c7 85 ?? f9 ff ff 6f 6d 65 2e c7 85 ?? f9 ff ff 65 78 65 00 } //1
		$a_03_1 = {f7 ff ff 49 45 58 50 c7 85 ?? f8 ff ff 4c 4f 52 45 c7 85 ?? f8 ff ff 2e 45 58 45 } //1
		$a_03_2 = {f6 ff ff 63 68 72 6f c7 85 ?? f7 ff ff 6d 65 2e 65 66 c7 ?? 04 f7 ff ff 78 65 } //1
		$a_03_3 = {fc ff ff 77 6b 73 63 c7 85 ?? fc ff ff 6c 69 76 2e c7 85 ?? fc ff ff 64 6c 6c 00 c7 85 ?? fc ff ff 5c 4c 6f 63 c7 85 ?? fc ff ff 61 74 69 6f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}