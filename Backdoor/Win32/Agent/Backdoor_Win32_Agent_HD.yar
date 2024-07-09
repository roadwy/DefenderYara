
rule Backdoor_Win32_Agent_HD{
	meta:
		description = "Backdoor:Win32/Agent.HD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {80 34 11 18 03 ca 42 3b d0 7c f2 } //2
		$a_02_1 = {8b 46 24 8b 4d 08 8d 04 48 0f b7 04 ?? 8b ?? 1c } //1
		$a_00_2 = {5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //1 \System32\svchost.exe -k
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}