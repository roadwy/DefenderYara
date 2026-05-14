
rule Trojan_Win32_Trickbot_MK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {f0 6e 00 74 00 c7 45 ?? 64 00 6c 00 c7 45 ?? 6c 00 00 00 c7 45 ?? 6b 00 65 00 c7 45 ?? 72 00 6e 00 c7 45 ?? 65 00 6c 00 c7 45 ?? 33 00 32 00 66 89 } //20
		$a_81_1 = {32 30 31 65 66 39 39 61 2d 37 66 61 30 2d 34 34 34 63 2d 39 33 39 39 2d 31 39 62 61 38 34 66 31 32 61 31 61 } //10 201ef99a-7fa0-444c-9399-19ba84f12a1a
		$a_81_2 = {25 77 73 63 6f 6d 70 75 74 65 72 64 65 66 61 75 6c 74 73 2e 65 78 65 } //5 %wscomputerdefaults.exe
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}