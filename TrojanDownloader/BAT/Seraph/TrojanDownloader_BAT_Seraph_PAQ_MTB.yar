
rule TrojanDownloader_BAT_Seraph_PAQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.PAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {67 72 61 62 70 66 6c 65 67 65 2d 65 74 74 6c 69 6e 67 65 6e 2e 64 65 2f 77 70 73 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f } //grabpflege-ettlingen.de/wps/loader/uploads/  1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d 57 72 69 74 65 } //1 MemoryStreamWrite
		$a_80_4 = {46 6f 6f 74 62 61 6c 6c } //Football  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}