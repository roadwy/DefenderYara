
rule Trojan_Win64_CountLoader_SNA_MTB{
	meta:
		description = "Trojan:Win64/CountLoader.SNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {48 54 41 20 52 75 6e 6e 65 72 } //1 HTA Runner
		$a_81_1 = {6d 73 68 74 61 2e 65 78 65 } //1 mshta.exe
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 62 75 72 6e 69 6e 67 2d 65 64 67 65 2e 73 62 73 2f 73 74 61 74 73 2f 72 61 6e 64 6f 6d 73 32 2f 6d 6f 6e 69 74 6f 72 2e 70 68 70 3f 71 3d } //1 https://burning-edge.sbs/stats/randoms2/monitor.php?q=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}