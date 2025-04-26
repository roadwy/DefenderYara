
rule Backdoor_BAT_Cobeacon_PA_MTB{
	meta:
		description = "Backdoor:BAT/Cobeacon.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 61 79 6c 6f 61 64 } //1 payload
		$a_00_1 = {48 6f 6c 6c 6f 77 65 72 } //1 Hollower
		$a_03_2 = {26 16 0d 2b ?? 07 09 04 09 91 28 ?? ?? ?? ?? 09 17 58 0d 09 04 8e 69 32 } //1
		$a_03_3 = {26 11 10 16 28 ?? ?? ?? ?? 13 11 11 11 6a 11 0e 6f ?? ?? ?? ?? 11 0e 6f ?? ?? ?? ?? 59 30 16 11 11 8d ?? ?? ?? ?? 13 05 11 0e 11 05 16 11 11 6f ?? ?? ?? ?? 26 de } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}