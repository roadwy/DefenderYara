
rule Backdoor_Win32_Mongall_MA_MTB{
	meta:
		description = "Backdoor:Win32/Mongall.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 7c 68 80 00 00 00 51 88 44 24 60 ff 15 ?? ?? ?? ?? 8d 54 24 7c 52 ff 15 ?? ?? ?? ?? 8b 40 0c 8b 08 8b 11 52 ff 15 } //1
		$a_03_1 = {83 c4 10 83 7d d0 ?? 74 ?? ff 75 d0 e8 ?? ?? ?? ?? 83 65 d0 ?? 59 8b 75 0c 8a 1e 46 84 db 89 75 0c 0f 85 } //1
		$a_01_2 = {73 6f 6d 6e 75 65 6b 2e 62 75 } //1 somnuek.bu
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}