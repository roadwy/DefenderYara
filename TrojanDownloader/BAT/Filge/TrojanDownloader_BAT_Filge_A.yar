
rule TrojanDownloader_BAT_Filge_A{
	meta:
		description = "TrojanDownloader:BAT/Filge.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 4c 00 32 00 64 00 6c 00 4c 00 6e 00 52 00 30 00 4c 00 32 00 46 00 77 00 61 00 53 00 38 00 78 00 4c 00 32 00 5a 00 70 00 62 00 47 00 56 00 7a 00 4c 00 7a 00 } //1 aHR0cDovL2dlLnR0L2FwaS8xL2ZpbGVzLz
		$a_01_1 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 4c 00 32 00 52 00 70 00 63 00 6d 00 56 00 6a 00 64 00 48 00 68 00 6c 00 65 00 43 00 35 00 75 00 5a 00 58 00 51 00 76 00 5a 00 54 00 } //1 aHR0cDovL2RpcmVjdHhleC5uZXQvZT
		$a_01_2 = {2f 00 63 00 20 00 63 00 64 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 20 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 42 00 } //2 /c cd %temp% & start /B
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}