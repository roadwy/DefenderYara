
rule Trojan_Win64_ClipBanker_WQ_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 70 61 6e 65 6c 2f 67 61 74 65 2e 70 68 70 } //1 /panel/gate.php
		$a_01_1 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 63 6c 69 70 62 6f 61 72 64 20 66 6f 72 20 63 72 79 70 74 6f 63 75 72 72 65 6e 63 79 20 61 64 64 72 65 73 73 65 73 } //1 Monitoring clipboard for cryptocurrency addresses
		$a_81_2 = {77 61 6c 6c 65 74 2e 20 52 65 70 6c 61 63 69 6e 67 20 } //1 wallet. Replacing 
		$a_81_3 = {5b 49 4e 46 4f 5d 20 74 6f 72 2e 65 78 65 20 66 6f 75 6e 64 2c 20 73 6b 69 70 70 69 6e 67 20 64 6f 77 6e 6c 6f 61 64 } //1 [INFO] tor.exe found, skipping download
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}