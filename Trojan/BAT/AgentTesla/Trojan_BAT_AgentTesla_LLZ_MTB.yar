
rule Trojan_BAT_AgentTesla_LLZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0c 12 02 28 90 01 03 0a 69 28 90 01 03 0a 07 17 58 0b 07 02 6f 90 01 03 0a 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 00 3d 54 00 65 00 73 00 74 00 2d 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f } //01 00 
		$a_81_2 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //01 00  System.Reflection.Assembly
		$a_81_3 = {54 65 73 74 2d 43 6f 6e 6e 65 63 74 69 6f 6e 20 77 77 77 2e 62 69 6e 67 2e 63 6f 6d } //01 00  Test-Connection www.bing.com
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}