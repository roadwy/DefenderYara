
rule Backdoor_Win32_Htbot_B{
	meta:
		description = "Backdoor:Win32/Htbot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 8d 4c 24 ?? 51 52 c7 44 24 ?? 01 00 cc ee ff 15 ?? ?? ?? ?? 83 f8 04 } //1
		$a_00_1 = {3f 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 67 00 65 00 74 00 62 00 61 00 63 00 6b 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //1 ?command=getbackconnect
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}