
rule Backdoor_Win32_Rbot_gen_D{
	meta:
		description = "Backdoor:Win32/Rbot.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 2f 59 8d 75 08 8b fc f3 a5 e8 90 01 04 81 c4 c0 00 00 00 68 f4 01 00 00 ff 15 90 01 04 eb 90 00 } //1
		$a_03_1 = {b9 2f 00 00 00 8d 75 08 8b fc f3 a5 e8 90 01 04 81 c4 c0 00 00 00 68 f4 01 00 00 ff 15 90 01 04 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}