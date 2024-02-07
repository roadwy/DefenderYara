
rule Backdoor_Win32_Qakbot_gen_A{
	meta:
		description = "Backdoor:Win32/Qakbot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_03_0 = {7d 29 8b 45 08 03 45 f8 0f be 08 8b 45 f8 99 f7 7d f0 0f be 82 90 01 04 33 c8 88 4d fc 8b 45 08 90 00 } //02 00 
		$a_03_1 = {7d 1f 8b 45 fc 99 f7 7d f4 8b 45 08 03 45 fc 8a 00 32 82 90 01 04 8b 4d 08 03 4d fc 88 01 eb d2 90 00 } //02 00 
		$a_03_2 = {75 0c c7 45 08 fd ff ff ff e9 67 01 00 00 56 68 00 04 00 00 68 90 01 04 ff 75 f8 53 90 00 } //02 00 
		$a_03_3 = {e9 03 02 00 00 6a 00 68 00 04 00 00 68 90 01 04 ff 75 f4 ff b5 90 00 } //03 00 
		$a_01_4 = {6a 6c 2f 6a 6c 6f 61 64 65 72 2e 70 6c 3f } //01 00  jl/jloader.pl?
		$a_01_5 = {25 73 5c 25 73 2e 63 62 } //01 00  %s\%s.cb
		$a_01_6 = {25 73 5c 25 73 2e 6b 63 62 } //01 00  %s\%s.kcb
		$a_01_7 = {71 62 6f 74 5f 76 65 72 73 69 6f 6e 3d 5b 25 73 5d } //01 00  qbot_version=[%s]
		$a_01_8 = {48 65 6c 6c 6f 39 39 39 57 30 72 6c 64 37 37 37 } //00 00  Hello999W0rld777
	condition:
		any of ($a_*)
 
}