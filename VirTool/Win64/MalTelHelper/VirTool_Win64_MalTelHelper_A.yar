
rule VirTool_Win64_MalTelHelper_A{
	meta:
		description = "VirTool:Win64/MalTelHelper.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 00 22 00 69 00 64 00 78 00 22 00 3a 00 25 00 69 00 2c 00 22 00 61 00 64 00 64 00 72 00 22 00 3a 00 25 00 6c 00 6c 00 75 00 2c 00 22 00 70 00 61 00 67 00 65 00 5f 00 61 00 64 00 64 00 72 00 22 00 3a 00 25 00 6c 00 6c 00 75 00 2c 00 22 00 73 00 69 00 7a 00 65 00 22 00 3a 00 25 00 7a 00 75 00 2c 00 22 00 73 00 74 00 61 00 74 00 65 00 22 00 3a 00 25 00 6c 00 75 00 2c 00 22 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 22 00 3a 00 22 00 25 00 73 00 22 00 2c 00 22 00 74 00 79 00 70 00 65 00 22 00 3a 00 22 00 25 00 73 00 22 00 7d 00 } //1 {"idx":%i,"addr":%llu,"page_addr":%llu,"size":%zu,"state":%lu,"protect":"%s","type":"%s"}
		$a_01_1 = {7b 00 22 00 74 00 79 00 70 00 65 00 22 00 3a 00 22 00 64 00 6c 00 6c 00 22 00 2c 00 22 00 66 00 75 00 6e 00 63 00 22 00 3a 00 } //1 {"type":"dll","func":
		$a_01_2 = {22 00 70 00 69 00 64 00 22 00 3a 00 25 00 6c 00 75 00 2c 00 22 00 74 00 69 00 64 00 22 00 3a 00 25 00 6c 00 75 00 7d 00 } //1 "pid":%lu,"tid":%lu}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}