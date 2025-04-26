
rule Trojan_BAT_AgentTesla_DFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 7e ?? ?? ?? 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? 06 9c 09 7e ?? ?? ?? 04 03 28 ?? ?? ?? 06 17 59 16 } //1
		$a_01_1 = {00 66 67 68 00 70 72 6f 6a 44 61 74 61 00 4b 31 00 78 79 7a 00 } //1
		$a_01_2 = {00 75 67 7a 31 00 75 67 7a 33 00 70 72 6f 6a 6e 61 6d 65 00 } //1 甀穧1杵㍺瀀潲湪浡e
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}