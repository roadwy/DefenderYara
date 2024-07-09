
rule Backdoor_Win32_Agent_GX{
	meta:
		description = "Backdoor:Win32/Agent.GX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 69 70 65 5c 5f 36 39 } //1 pipe\_69
		$a_01_1 = {5c 74 65 6d 70 2e 74 65 6d 70 } //1 \temp.temp
		$a_03_2 = {41 8a 94 38 ?? ?? 00 10 8a 99 ?? ?? 00 10 32 d3 88 97 ?? ?? 00 10 75 06 88 9f ?? ?? 00 10 47 3b 7d fc 7c ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}