
rule Trojan_BAT_Lokibot_GM_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 00 01 25 16 03 16 9a a2 25 17 03 17 9a a2 25 18 04 a2 0a } //8
		$a_01_1 = {73 67 74 61 74 68 61 6d 2f 70 75 74 74 79 2f 30 } //1 sgtatham/putty/0
		$a_01_2 = {54 72 69 66 33 32 } //1 Trif32
		$a_01_3 = {31 39 30 33 31 36 31 32 33 31 35 32 5a 30 } //1 190316123152Z0
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}