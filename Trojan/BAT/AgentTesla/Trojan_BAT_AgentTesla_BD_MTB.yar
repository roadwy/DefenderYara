
rule Trojan_BAT_AgentTesla_BD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a 0c 1e 8d 90 01 04 0d 08 28 90 01 04 20 90 01 04 28 90 01 04 6f 90 01 04 6f 90 01 04 13 04 11 04 16 09 16 1e 28 90 01 04 07 09 6f 90 01 04 07 18 6f 90 01 04 07 6f 90 01 04 03 16 03 8e 69 6f 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_BD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {fa 01 33 00 02 00 00 01 00 00 00 3c 00 00 00 0b 00 00 00 0e 00 00 00 1f 00 00 00 16 00 00 00 50 00 00 00 } //1
		$a_01_1 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 } //1 CryptoObfuscator_Output
		$a_01_2 = {55 73 65 72 73 5c 56 49 43 54 4f 52 } //1 Users\VICTOR
		$a_01_3 = {57 45 52 47 48 47 48 4a 48 4a 46 2e 70 64 62 } //1 WERGHGHJHJF.pdb
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_BD_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.BD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 65 33 35 66 39 33 38 39 2d 35 63 66 32 2d 34 65 61 37 2d 39 38 34 30 2d 66 36 66 66 35 34 36 30 37 37 64 61 } //1 $e35f9389-5cf2-4ea7-9840-f6ff546077da
		$a_01_1 = {42 6c 69 74 2e 65 78 65 } //1 Blit.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}