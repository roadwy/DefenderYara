
rule Trojan_Win64_Lazy_LMQ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 3c 2b 49 8d 0c 5e 48 6b d3 fd 44 8b cf 4c 8d 05 92 80 00 00 48 83 c2 31 48 03 cb } //10
		$a_81_1 = {70 75 64 69 6d 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4d 69 6e 65 5c 78 36 34 5c 44 65 62 75 67 5c 4d 69 6e 65 } //20 pudim\source\repos\Mine\x64\Debug\Mine
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*20) >=30
 
}