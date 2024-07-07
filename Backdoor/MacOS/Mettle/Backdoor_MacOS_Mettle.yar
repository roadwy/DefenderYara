
rule Backdoor_MacOS_Mettle{
	meta:
		description = "Backdoor:MacOS/Mettle,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 6d 65 74 74 6c 65 2e 63 } //1 /mettle/mettle/src/mettle.c
		$a_00_1 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 63 32 5f 68 74 74 70 2e 63 } //1 /mettle/mettle/src/c2_http.c
		$a_00_2 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 62 75 66 66 65 72 65 76 2e 63 } //1 /mettle/mettle/src/bufferev.c
		$a_00_3 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 63 68 61 6e 6e 65 6c 2e 63 } //1 /mettle/mettle/src/channel.c
		$a_00_4 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 63 6f 72 65 61 70 69 2e 63 } //1 /mettle/mettle/src/coreapi.c
		$a_00_5 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 70 72 6f 63 65 73 73 2e 63 } //1 /mettle/mettle/src/process.c
		$a_00_6 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 73 65 72 76 69 63 65 2e 63 } //1 /mettle/mettle/src/service.c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}