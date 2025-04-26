
rule TrojanDownloader_BAT_Seraph_ABES_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 1c 12 03 2b 1b 2b 20 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a de 17 08 2b e1 28 ?? ?? ?? 0a 2b de 06 2b dd } //3
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}