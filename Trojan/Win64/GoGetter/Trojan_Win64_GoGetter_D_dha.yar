
rule Trojan_Win64_GoGetter_D_dha{
	meta:
		description = "Trojan:Win64/GoGetter.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 78 79 2f 70 6b 67 2f 63 6c 69 65 6e 74 2e 28 2a 43 6c 69 65 6e 74 29 2e 63 6f 6e 6e 65 63 74 54 6f 52 65 6d 6f 74 65 } //10 proxy/pkg/client.(*Client).connectToRemote
		$a_01_1 = {70 72 6f 78 79 2f 70 6b 67 2f 63 6c 69 65 6e 74 2e 28 2a 43 6c 69 65 6e 74 29 2e 68 61 6e 64 6c 65 53 65 73 73 69 6f 6e } //10 proxy/pkg/client.(*Client).handleSession
		$a_01_2 = {70 72 6f 78 79 2f 70 6b 67 2f 63 6c 69 65 6e 74 2e 28 2a 43 6c 69 65 6e 74 29 2e 63 6f 6e 6e 65 63 74 54 6f 54 61 72 67 65 74 } //10 proxy/pkg/client.(*Client).connectToTarget
		$a_01_3 = {70 72 6f 78 79 2f 70 6b 67 2f 63 6c 69 65 6e 74 2e 68 61 6e 64 6c 65 43 6f 6e 6e 65 63 74 69 6f 6e } //10 proxy/pkg/client.handleConnection
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}