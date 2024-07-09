
rule VirTool_BAT_Peckpai_A{
	meta:
		description = "VirTool:BAT/Peckpai.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 74 73 65 6c 66 43 72 79 70 74 00 } //1 瑉敳晬牃灹t
		$a_01_1 = {4d 79 61 73 73 00 } //1 祍獡s
		$a_03_2 = {2e 72 65 73 6f 75 72 63 65 73 [0-60] 47 69 00 6e 00 6a 00 [0-70] 47 70 00 61 00 79 00 } //10
		$a_01_3 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00 4d 00 61 00 69 00 6e 00 65 00 6e 00 74 00 72 00 79 00 } //1 Resource.Mainentry
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1) >=11
 
}