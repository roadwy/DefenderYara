
rule HackTool_Win64_Killgent_DA_MTB{
	meta:
		description = "HackTool:Win64/Killgent.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {42 59 4f 56 44 20 50 72 6f 63 65 73 73 20 4b 69 6c 6c 65 72 } //BYOVD Process Killer  1
		$a_80_1 = {42 6c 61 63 6b 53 6e 75 66 6b 69 6e 4b 69 6c 6c 73 } //BlackSnufkinKills  1
		$a_80_2 = {5b 21 5d 20 4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 3a } //[!] Killing process:  1
		$a_80_3 = {76 69 72 61 67 74 36 34 2e 73 79 73 } //viragt64.sys  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}