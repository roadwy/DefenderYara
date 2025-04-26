
rule Trojan_BAT_Zusy_HNF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c 83 45 31 c0 49 01 c9 43 8a 34 02 40 84 f6 74 } //2
		$a_03_1 = {47 65 74 50 72 6f 63 41 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 64 64 72 65 73 73 } //1
		$a_01_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //1 CreateProcess
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}