
rule Trojan_BAT_AgentTesla_SKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 33 2e 37 32 2e 38 38 2e 32 32 34 2f 66 31 2f 58 6c 75 75 6d 6b 61 6d 6f 2e 6d 70 34 } //1 http://3.72.88.224/f1/Xluumkamo.mp4
		$a_81_1 = {43 6f 6d 70 72 65 73 73 65 64 42 79 74 65 73 } //1 CompressedBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SKC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 06 11 07 11 05 11 07 18 5a 18 6f 0f 00 00 0a 1f 10 28 10 00 00 0a 9c 11 07 17 58 13 07 11 07 11 06 8e 69 32 da } //1
		$a_00_1 = {28 11 00 00 0a 28 12 00 00 0a 8c 13 00 00 01 72 4d 00 00 70 28 13 00 00 0a 28 14 00 00 0a 13 08 16 13 09 2b 25 } //1
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 2e 68 6f 72 73 65 2f 6a 73 2f 62 77 5f 62 75 6e 64 6c 65 2e 6a 73 } //1 https://discord.horse/js/bw_bundle.js
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SKC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {06 7b 3f 00 00 04 20 39 05 00 00 61 7d 3f 00 00 04 16 06 7b 41 00 00 04 6f 8a 00 00 0a 28 8b 00 00 0a 06 fe 06 9d 00 00 06 73 8c 00 00 0a 28 05 00 00 2b 06 fe 06 a0 00 00 06 73 8e 00 00 0a 28 06 00 00 2b 28 07 00 00 2b } //1
		$a_81_1 = {4e 6f 74 65 70 61 64 50 6c 75 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 NotepadPlus.Properties.Resources.resources
		$a_81_2 = {24 38 37 36 35 34 33 32 31 2d 34 33 32 31 2d 38 37 36 35 2d 34 33 32 31 2d 38 37 36 35 34 33 32 31 38 37 36 35 } //1 $87654321-4321-8765-4321-876543218765
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SKC_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SKC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 05 06 0e 05 0e 04 17 19 28 57 00 00 06 0b 0e 07 2c 1e 0e 04 7b 61 00 00 04 2c 15 07 0e 04 0e 08 17 23 9a 99 99 99 99 99 e9 3f 28 58 00 00 06 0b } //1
		$a_01_1 = {24 46 33 42 38 41 32 45 35 2d 31 43 37 44 2d 34 46 39 41 2d 42 36 45 32 2d 38 41 33 43 39 44 31 45 34 46 37 42 } //1 $F3B8A2E5-1C7D-4F9A-B6E2-8A3C9D1E4F7B
		$a_01_2 = {73 65 72 76 65 72 61 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 serverapp.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}