
rule Backdoor_Linux_FegratSrv_B_dha{
	meta:
		description = "Backdoor:Linux/FegratSrv.B!dha,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 65 64 46 6c 61 72 65 2f 52 65 64 46 6c 61 72 65 2f 73 65 72 76 65 72 2f 70 61 79 6c 6f 61 64 67 65 6e 2e 62 61 63 6b 65 6e 64 73 } //1 RedFlare/RedFlare/server/payloadgen.backends
		$a_00_1 = {52 65 64 46 6c 61 72 65 2f 52 65 64 46 6c 61 72 65 2f 73 65 72 76 65 72 2f 64 65 70 6c 6f 79 2f 70 72 6f 76 69 73 69 6f 6e 65 72 73 2f 67 6f 72 61 74 2e 72 75 6e 53 68 65 6c 6c } //1 RedFlare/RedFlare/server/deploy/provisioners/gorat.runShell
		$a_00_2 = {52 65 64 46 6c 61 72 65 2f 52 65 64 46 6c 61 72 65 2f 73 65 72 76 65 72 2f 73 74 6f 72 61 67 65 2f 70 6f 73 74 67 72 65 73 2e 69 6e 69 74 69 61 6c 42 65 61 63 6f 6e 44 75 72 43 68 65 63 6b } //1 RedFlare/RedFlare/server/storage/postgres.initialBeaconDurCheck
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}