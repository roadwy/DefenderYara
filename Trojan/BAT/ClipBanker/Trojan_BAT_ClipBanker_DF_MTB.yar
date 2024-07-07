
rule Trojan_BAT_ClipBanker_DF_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 44 6f 76 4c 33 46 71 63 58 42 78 61 57 46 74 61 44 49 75 5a 58 52 6c 63 6d 35 68 62 47 68 76 63 33 51 75 61 57 35 6d 62 79 38 3d } //1 aHR0cDovL3FqcXBxaWFtaDIuZXRlcm5hbGhvc3QuaW5mby8=
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 Software\Microsoft\Windows\CurrentVersion\Run\
		$a_81_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 SELECT * FROM AntiVirusProduct
		$a_81_3 = {52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 RemoteDebuggerPresent
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}