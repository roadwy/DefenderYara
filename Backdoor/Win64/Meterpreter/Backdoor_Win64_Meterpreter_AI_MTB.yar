
rule Backdoor_Win64_Meterpreter_AI_MTB{
	meta:
		description = "Backdoor:Win64/Meterpreter.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 65 6e 67 77 65 6e 68 75 61 66 65 6e 67 77 65 6e 68 75 61 66 65 6e 67 77 65 6e 68 75 61 2e } //1 fengwenhuafengwenhuafengwenhua.
		$a_01_1 = {2e 63 41 54 47 42 42 4f } //1 .cATGBBO
		$a_01_2 = {42 4b 79 4b 4c 65 47 5a } //1 BKyKLeGZ
		$a_01_3 = {6d 41 40 40 4b 4d 5a 47 41 40 } //1 mA@@KMZGA@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}