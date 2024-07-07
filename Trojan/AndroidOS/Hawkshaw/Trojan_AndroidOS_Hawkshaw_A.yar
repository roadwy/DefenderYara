
rule Trojan_AndroidOS_Hawkshaw_A{
	meta:
		description = "Trojan:AndroidOS/Hawkshaw.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 73 20 6e 6f 74 20 61 20 66 69 6c 65 2c 20 61 62 6f 72 74 69 6e 67 20 75 70 6c 6f 61 64 } //1 is not a file, aborting upload
		$a_01_1 = {50 75 73 68 46 69 6c 65 54 75 73 3a 20 55 70 6c 6f 61 64 20 73 74 61 72 74 69 6e 67 2e 2e 2e } //1 PushFileTus: Upload starting...
		$a_01_2 = {41 64 64 43 61 6c 6c 4c 6f 67 3a 20 59 6f 75 20 64 6f 6e 27 74 20 68 61 76 65 20 70 65 72 6d 69 73 73 69 6f 6e 20 74 6f 20 77 72 69 74 65 20 63 61 6c 6c 20 6c 6f 67 73 } //1 AddCallLog: You don't have permission to write call logs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}