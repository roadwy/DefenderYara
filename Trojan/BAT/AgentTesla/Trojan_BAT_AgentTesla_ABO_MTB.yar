
rule Trojan_BAT_AgentTesla_ABO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 bf 08 00 00 95 6e 31 03 16 2b 01 17 7e 3c 00 00 04 16 9a 20 97 0e 00 00 95 5a 7e 3c 00 00 04 16 9a 20 24 0e 00 00 95 58 61 81 07 00 00 01 } //2
		$a_01_1 = {95 61 7e 21 00 00 04 20 35 09 00 00 95 2e 03 16 2b 01 17 17 59 7e 21 00 00 04 20 1a 13 00 00 95 5f 7e 21 00 00 04 20 a1 0d 00 00 95 61 58 81 05 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_ABO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {35 00 35 00 52 00 37 00 53 00 50 00 43 00 34 00 42 00 35 00 34 00 4a 00 51 00 47 00 4e 00 34 00 43 00 35 00 34 00 37 00 48 00 34 00 } //1 55R7SPC4B54JQGN4C547H4
		$a_01_5 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_6 = {24 37 32 62 34 38 61 38 31 2d 32 37 34 62 2d 34 32 61 62 2d 62 31 64 63 2d 65 62 32 35 33 61 37 38 39 36 31 63 } //1 $72b48a81-274b-42ab-b1dc-eb253a78961c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}