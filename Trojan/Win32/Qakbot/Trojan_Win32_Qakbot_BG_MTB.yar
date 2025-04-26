
rule Trojan_Win32_Qakbot_BG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 72 6f 61 64 62 69 6c 6c } //1 broadbill
		$a_01_1 = {65 6e 6c 61 72 67 65 61 62 6c 65 6e 65 73 73 } //1 enlargeableness
		$a_01_2 = {6c 69 70 70 65 64 } //1 lipped
		$a_01_3 = {6d 6f 6e 6f 74 68 65 69 73 74 } //1 monotheist
		$a_01_4 = {70 68 61 72 79 6e 67 65 6d 70 68 72 61 78 69 73 } //1 pharyngemphraxis
		$a_01_5 = {73 63 72 69 62 62 6c 65 6f 6d 61 6e 69 61 } //1 scribbleomania
		$a_01_6 = {70 6c 61 74 79 70 6f 64 } //1 platypod
		$a_01_7 = {75 6e 74 75 72 70 65 6e 74 69 6e 65 64 } //1 unturpentined
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}