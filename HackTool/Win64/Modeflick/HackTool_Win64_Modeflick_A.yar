
rule HackTool_Win64_Modeflick_A{
	meta:
		description = "HackTool:Win64/Modeflick.A,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 89 5c 24 08 48 89 6c 24 10 57 48 83 ec 20 83 } //50
		$a_01_1 = {48 8b 41 30 48 8b 49 38 48 ff 25 } //50
		$a_01_2 = {48 8b 49 c8 48 8b 01 48 8b 40 08 48 ff 25 } //50
		$a_00_3 = {49 00 49 00 44 00 5f 00 49 00 45 00 6e 00 75 00 6d 00 54 00 66 00 49 00 6e 00 70 00 75 00 74 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 } //1 IID_IEnumTfInputProcessorProfiles
		$a_00_4 = {37 00 31 00 43 00 36 00 45 00 37 00 34 00 44 00 2d 00 30 00 46 00 32 00 38 00 2d 00 31 00 31 00 44 00 38 00 2d 00 41 00 38 00 32 00 41 00 2d 00 30 00 30 00 30 00 36 00 35 00 42 00 38 00 34 00 34 00 33 00 35 00 43 00 } //1 71C6E74D-0F28-11D8-A82A-00065B84435C
		$a_00_5 = {49 49 44 5f 49 45 6e 75 6d 54 66 49 6e 70 75 74 50 72 6f 63 65 73 73 6f 72 50 72 6f 66 69 6c 65 73 } //1 IID_IEnumTfInputProcessorProfiles
		$a_00_6 = {37 31 43 36 45 37 34 44 2d 30 46 32 38 2d 31 31 44 38 2d 41 38 32 41 2d 30 30 30 36 35 42 38 34 34 33 35 43 } //1 71C6E74D-0F28-11D8-A82A-00065B84435C
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=101
 
}