
rule HackTool_Win64_ITuneByPass_MBWK_MTB{
	meta:
		description = "HackTool:Win64/ITuneByPass.MBWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f [0-2f] 2f 74 6f 6b 65 6e 73 6d 69 74 68 2f 63 6d 64 } //2
		$a_03_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f [0-2f] 2f 6d 6f 75 73 65 74 72 61 70 } //1
		$a_01_2 = {69 6e 74 75 6e 65 2d 62 79 70 61 73 73 72 65 73 70 6f 6e 73 65 5f 74 79 70 65 5f 61 63 74 69 76 65 } //1 intune-bypassresponse_type_active
		$a_03_3 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 67 6f 2f 73 72 63 2f 72 75 6e 74 69 6d 65 2f [0-2f] 2e 67 6f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}