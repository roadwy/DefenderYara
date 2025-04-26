
rule TrojanSpy_BAT_Ruzmoil_A{
	meta:
		description = "TrojanSpy:BAT/Ruzmoil.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 75 4e 6b 5f 66 6b 71 4e 57 61 65 31 31 30 30 32 37 32 38 35 33 } //1 JuNk_fkqNWae1100272853
		$a_01_1 = {49 6d 76 75 5f 46 75 63 6b } //1 Imvu_Fuck
		$a_01_2 = {4b 65 79 6c 6f 67 67 65 72 5f 53 74 75 62 } //1 Keylogger_Stub
		$a_01_3 = {63 64 5f 6b 65 79 74 78 74 5f 43 72 65 61 74 65 } //1 cd_keytxt_Create
		$a_01_4 = {43 52 59 50 54 50 52 4f 54 45 43 54 5f 50 52 4f 4d 50 54 5f 4f 4e 5f 50 52 4f 54 45 43 54 } //1 CRYPTPROTECT_PROMPT_ON_PROTECT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}