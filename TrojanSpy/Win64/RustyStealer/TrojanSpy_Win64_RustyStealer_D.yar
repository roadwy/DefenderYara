
rule TrojanSpy_Win64_RustyStealer_D{
	meta:
		description = "TrojanSpy:Win64/RustyStealer.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 5f 6c 69 73 74 6b 65 65 70 61 6c 69 76 65 5f 74 69 6d 65 69 73 5f 6b 69 6c 6c 65 72 70 65 72 73 69 73 74 65 6e 63 65 5f 69 6e 73 74 61 6c 6c 65 64 65 6e 61 62 6c 65 5f 6b 65 79 6c 6f 67 67 65 72 6b 65 79 6c 6f 67 67 65 72 5f 70 61 74 68 73 74 72 75 63 74 20 43 6f 6e 66 69 67 44 61 74 61 65 6e 63 72 79 70 74 65 64 5f 64 61 74 61 73 74 72 75 63 74 20 43 6f 6e 66 69 67 } //1 server_listkeepalive_timeis_killerpersistence_installedenable_keyloggerkeylogger_pathstruct ConfigDataencrypted_datastruct Config
		$a_01_1 = {73 6c 6b 74 69 6b 70 69 70 6b 70 73 74 72 75 63 74 20 43 6f 6e 66 69 67 } //1 slktikpipkpstruct Config
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}