
rule Trojan_BAT_AgentTesla_MBXU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 71 6c 72 44 59 34 51 5a 43 66 35 31 4e 6a 54 69 77 } //3 SqlrDY4QZCf51NjTiw
		$a_01_1 = {47 42 2d 6c 65 73 73 6f 6e 2d 66 6f 72 6d 73 2e 67 2e 72 65 73 6f 75 72 63 65 } //2 GB-lesson-forms.g.resource
		$a_01_2 = {6c 44 37 4e 52 37 4b 47 77 4b 66 39 69 4d 61 54 66 79 } //1 lD7NR7KGwKf9iMaTfy
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}