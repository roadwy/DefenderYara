
rule Trojan_BAT_AgentTesla_BS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_02_0 = {13 05 2b bd 16 0a 18 13 05 2b b6 04 03 61 1f 60 59 06 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? 1e 13 05 2b a0 19 2b f9 14 0b 16 13 05 2b 96 } //10
		$a_80_1 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  1
		$a_80_2 = {73 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //set_ConnectionString  1
		$a_80_3 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  1
		$a_80_4 = {43 6f 72 72 75 70 74 4c 6f 61 64 } //CorruptLoad  1
		$a_80_5 = {57 72 69 74 65 52 65 73 50 61 73 73 77 6f 72 64 } //WriteResPassword  1
		$a_80_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=16
 
}