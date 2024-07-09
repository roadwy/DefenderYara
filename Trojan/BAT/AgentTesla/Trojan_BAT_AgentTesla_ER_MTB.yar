
rule Trojan_BAT_AgentTesla_ER_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {16 0a 16 0b 03 0c 16 0d 2b 0c 08 09 94 0b 06 07 d6 0a 09 17 d6 0d 09 08 8e 69 32 ee 02 } //5
		$a_02_1 = {25 16 02 28 ?? ?? ?? 06 13 04 12 04 28 ?? ?? ?? 06 a2 90 09 06 00 17 8d ?? ?? ?? 01 } //5
		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_ER_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {01 57 15 a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 bd 00 00 00 15 00 00 00 bf } //2
		$a_01_1 = {4b 00 6e 00 6f 00 77 00 5f 00 69 00 66 00 5f 00 59 00 6f 00 75 00 72 00 5f 00 47 00 69 00 72 00 6c 00 66 00 72 00 69 00 65 00 6e 00 64 00 5f 00 49 00 73 00 5f 00 48 00 6f 00 72 00 6e 00 79 00 } //1 Know_if_Your_Girlfriend_Is_Horny
		$a_01_2 = {68 00 61 00 68 00 6e 00 32 00 30 00 31 00 34 00 2f 00 4d 00 6f 00 76 00 69 00 65 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //1 hahn2014/MovieBrowser
		$a_01_3 = {42 00 75 00 6e 00 69 00 35 00 35 00 35 00 66 00 75 00 } //1 Buni555fu
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_ER_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 64 63 33 66 62 39 62 62 2d 35 32 30 64 2d 34 38 61 30 2d 39 62 65 33 2d 38 34 32 31 63 30 37 32 37 33 61 36 } //20 $dc3fb9bb-520d-48a0-9be3-8421c07273a6
		$a_81_1 = {50 61 73 73 43 72 79 70 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //20 PassCrypt.My.Resources
		$a_81_2 = {43 72 69 70 74 61 74 6f 72 65 20 69 6e 20 41 45 53 32 35 36 20 64 69 20 70 61 73 73 77 6f 72 64 20 65 20 64 61 74 69 20 70 65 72 73 6f 6e 61 6c 69 } //1 Criptatore in AES256 di password e dati personali
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=26
 
}