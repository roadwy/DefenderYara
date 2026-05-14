
rule Trojan_Win64_BypassUAC_MK_MTB{
	meta:
		description = "Trojan:Win64/BypassUAC.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,55 00 55 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 3a } //10 Injection successful:
		$a_01_1 = {62 6f 74 6b 69 6c 6c 65 72 5f 73 63 61 6e } //20 botkiller_scan
		$a_01_2 = {46 6f 72 6d 20 47 72 61 62 62 65 72 20 73 74 61 72 74 65 64 } //15 Form Grabber started
		$a_81_3 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 45 76 65 6e 74 43 6f 6e 73 75 6d 65 72 2e 4e 61 6d 65 3d 22 42 6f 74 6e 65 74 43 6f 6e 73 75 6d 65 72 5f } //20 CommandLineEventConsumer.Name="BotnetConsumer_
		$a_01_4 = {70 65 72 73 69 73 74 65 6e 63 65 } //10 persistence
		$a_01_5 = {50 72 6f 63 65 73 73 20 68 69 64 64 65 6e 3a } //10 Process hidden:
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*15+(#a_81_3  & 1)*20+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=85
 
}