
rule Trojan_BAT_AgentTesla_NLV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 18 5a 18 6f 30 00 00 0a 1f 10 28 b0 00 00 0a 9c 08 17 58 0c 08 20 00 58 00 00 fe 04 2d de } //1
		$a_01_1 = {2f 00 61 00 70 00 70 00 2e 00 78 00 61 00 6d 00 6c } //1
		$a_01_2 = {59 00 75 00 41 00 6f 00 20 00 32 00 30 00 31 00 32 } //1
		$a_80_3 = {42 61 63 6b 67 72 6f 75 6e 64 57 69 6e 64 6f 77 2e 78 61 6d 6c } //BackgroundWindow.xaml  1
		$a_80_4 = {49 52 65 6d 6f 74 69 6e 67 46 6f 72 6d 61 74 74 65 72 2e 43 6f 6e 74 69 6e 75 61 74 69 6f 6e 57 72 61 70 70 65 72 } //IRemotingFormatter.ContinuationWrapper  1
		$a_80_5 = {58 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //XCreateInstance  1
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_7 = {4d 6f 74 69 76 61 74 65 44 65 73 6b 74 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MotivateDesktop.Properties.Resources.resources
		$a_80_8 = {56 61 6c 33 } //Val3  1
		$a_80_9 = {56 61 6c 31 } //Val1  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}