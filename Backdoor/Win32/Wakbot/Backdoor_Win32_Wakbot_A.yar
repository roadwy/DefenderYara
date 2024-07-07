
rule Backdoor_Win32_Wakbot_A{
	meta:
		description = "Backdoor:Win32/Wakbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 b1 04 01 00 00 8a 04 3e 8a 14 0a 3a c2 74 09 84 c0 74 05 32 c2 88 04 90 04 01 01 3e 90 00 } //2
		$a_03_1 = {56 ff 75 ec e8 90 01 02 00 00 ff 55 90 04 01 01 ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}