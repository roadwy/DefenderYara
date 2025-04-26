
rule Trojan_BAT_Sabsik_FGR_MTB{
	meta:
		description = "Trojan:BAT/Sabsik.FGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {fa 25 33 00 16 00 00 01 ?? ?? ?? 11 ?? ?? ?? 15 ?? ?? ?? f2 ?? ?? ?? 10 ?? ?? ?? 31 ?? ?? ?? 0a ?? ?? ?? 1c } //10
		$a_80_1 = {48 69 67 68 3a 7b 30 7d 2c 20 4c 6f 77 3a 7b 31 7d } //High:{0}, Low:{1}  3
		$a_80_2 = {6c 70 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 } //lpCurrentDirectory  3
		$a_80_3 = {6c 70 53 74 61 72 74 75 70 49 6e 66 6f } //lpStartupInfo  3
		$a_80_4 = {6c 70 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e } //lpProcessInformation  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}