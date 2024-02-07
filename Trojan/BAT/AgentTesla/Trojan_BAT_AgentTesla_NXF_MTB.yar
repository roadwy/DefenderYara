
rule Trojan_BAT_AgentTesla_NXF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 73 6f 6d 66 66 66 66 66 66 66 66 66 66 66 65 64 69 72 65 63 74 6f 72 79 5c } //01 00  C:\somfffffffffffedirectory\
		$a_81_1 = {6e 69 75 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 68 69 75 } //01 00  niudddddddddddddddddhiu
		$a_81_2 = {66 64 73 66 66 66 66 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 64 66 66 73 64 66 } //01 00  fdsffffhhhhhhhhhhhhhhhhhhhhhhhhdffsdf
		$a_81_3 = {73 64 64 6b 66 66 73 68 64 6a 66 66 66 67 6a 68 6b 64 6b 73 67 63 61 66 70 } //01 00  sddkffshdjfffgjhkdksgcafp
		$a_81_4 = {66 73 64 68 66 68 66 64 66 20 66 } //01 00  fsdhfhfdf f
		$a_81_5 = {61 64 73 73 73 73 73 73 73 73 73 73 73 61 } //01 00  adsssssssssssa
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}