
rule Trojan_Win64_Zusy_HNL_MTB{
	meta:
		description = "Trojan:Win64/Zusy.HNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {15 6a 73 6f 6e 3a 22 69 74 65 72 61 74 6f 72 5f 73 6c 69 63 65 22 } //1 樕潳㩮椢整慲潴彲汳捩≥
		$a_01_1 = {00 6d 61 69 6e 2e 44 4c 4c 57 4d 61 69 6e 00 00 00 00 00 00 00 00 00 } //2
		$a_01_2 = {6a 73 6f 6e 3a 22 63 6c 69 65 6e 74 5f 69 64 2c 6f 6d 69 74 65 6d 70 74 79 } //3 json:"client_id,omitempty
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}