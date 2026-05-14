
rule Trojan_BAT_NexilBreak_A_dha{
	meta:
		description = "Trojan:BAT/NexilBreak.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 00 79 00 6e 00 61 00 6d 00 69 00 74 00 65 00 2e 00 50 00 61 00 74 00 68 00 } //1 Dynamite.Path
		$a_01_1 = {50 00 69 00 63 00 6b 00 2e 00 46 00 69 00 6c 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //1 Pick.FileManager
		$a_01_2 = {70 00 66 00 64 00 20 00 65 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 3a 00 } //1 pfd exception:
		$a_01_3 = {6f 00 73 00 64 00 20 00 65 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 3a 00 } //1 osd exception:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}