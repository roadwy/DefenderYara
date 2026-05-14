
rule Trojan_Win64_Meterpreter_AHA_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 20 6b 65 79 6c 6f 67 5f 73 74 61 72 74 20 74 6f 20 28 72 65 29 73 74 61 72 74 20 77 69 74 68 20 65 6e 68 61 6e 63 65 64 20 6f 75 74 70 75 74 2e } //40 Run keylog_start to (re)start with enhanced output.
		$a_01_1 = {63 6c 69 70 5f 68 69 6a 61 63 6b 5f 73 74 61 72 74 } //30 clip_hijack_start
		$a_01_2 = {6a 69 6e 78 5f 61 67 65 6e 74 } //20 jinx_agent
		$a_01_3 = {65 78 66 69 6c 5f 68 74 74 70 73 5f 66 69 6c 65 } //10 exfil_https_file
	condition:
		((#a_01_0  & 1)*40+(#a_01_1  & 1)*30+(#a_01_2  & 1)*20+(#a_01_3  & 1)*10) >=90
 
}