
rule VirTool_Win64_Titan_A{
	meta:
		description = "VirTool:Win64/Titan.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 65 63 74 20 4b 76 67 6b 66 73 73 46 6f 72 6d 3a 20 54 4b 76 67 6b 66 73 73 46 6f 72 6d } //1 object KvgkfssForm: TKvgkfssForm
		$a_01_1 = {43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //1 CryptDestroyKey
		$a_01_2 = {6f 62 6a 65 63 74 20 50 69 79 62 71 62 61 46 6f 72 6d 3a 20 54 50 69 79 62 71 62 61 46 6f 72 6d } //1 object PiybqbaForm: TPiybqbaForm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}