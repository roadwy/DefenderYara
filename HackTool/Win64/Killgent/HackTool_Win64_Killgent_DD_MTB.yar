
rule HackTool_Win64_Killgent_DD_MTB{
	meta:
		description = "HackTool:Win64/Killgent.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4b 69 6c 6c 20 45 44 52 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Kill EDR Successfully
		$a_81_1 = {50 6c 65 61 73 65 20 73 74 61 72 74 20 77 69 74 68 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 Please start with administrator
		$a_81_2 = {44 72 69 76 65 72 20 6c 6f 61 64 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Driver loaded successfully
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}