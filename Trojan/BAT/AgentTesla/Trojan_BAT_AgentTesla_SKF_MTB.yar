
rule Trojan_BAT_AgentTesla_SKF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {08 11 04 07 11 04 91 09 11 04 09 6f 37 00 00 0a 5d 6f 38 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da } //1
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 69 6e 73 70 69 72 65 63 6f 6c 6c 65 67 65 2e 63 6f 2e 75 6b 2f 74 72 61 73 68 73 73 2f } //1 https://inspirecollege.co.uk/trashss/
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SKF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 64 75 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Product.Properties.Resources
		$a_81_1 = {2f 2f 31 36 37 2e 31 36 30 2e 31 36 36 2e 32 30 35 2f 31 35 37 31 2e 62 69 6e } //1 //167.160.166.205/1571.bin
		$a_00_2 = {00 7e 08 00 00 04 06 7e 08 00 00 04 06 91 20 23 06 00 00 59 d2 9c 00 06 17 58 0a 06 7e 08 00 00 04 8e 69 fe 04 0b 07 2d d7 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SKF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {13 0c 11 0c 1f 7b 61 20 ff 00 00 00 5f 13 0d 11 0d 20 c8 01 00 00 58 20 00 01 00 00 5e 13 0d 11 0d 16 fe 01 13 0e 11 0e 2c 03 17 13 0d 09 11 0b 07 11 0b 91 11 04 11 0c 95 61 d2 9c 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0f 11 0f 3a 66 ff ff ff } //1
		$a_81_1 = {41 50 37 48 39 48 35 4f 49 34 34 37 38 46 38 43 48 30 35 46 47 41 } //1 AP7H9H5OI4478F8CH05FGA
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SKF_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {02 06 07 28 05 00 00 06 0c 04 03 6f 40 00 00 0a 59 0d 03 08 09 28 06 00 00 06 07 17 58 0b 07 02 6f 41 00 00 0a 2f 09 03 6f 40 00 00 0a 04 32 d0 } //1
		$a_81_1 = {4d 65 6d 6f 72 69 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Memori.Properties
		$a_81_2 = {24 33 61 31 36 37 32 65 30 2d 30 35 36 34 2d 34 39 32 38 2d 62 62 66 37 2d 35 37 32 63 63 37 65 61 39 32 34 66 } //1 $3a1672e0-0564-4928-bbf7-572cc7ea924f
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SKF_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 07 28 f0 00 00 06 0c 04 03 6f f6 00 00 0a 59 0d 03 08 09 28 f2 00 00 06 00 03 08 09 28 f4 00 00 06 00 03 04 28 f5 00 00 06 00 00 07 17 58 0b 07 02 6f f7 00 00 0a fe 04 13 04 11 04 2d bf } //1
		$a_01_1 = {43 6f 6e 42 6f 6f 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ConBook.Properties.Resources
		$a_01_2 = {43 6f 6e 42 6f 6f 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ConBook.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}