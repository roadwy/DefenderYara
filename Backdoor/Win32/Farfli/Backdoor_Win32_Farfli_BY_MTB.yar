
rule Backdoor_Win32_Farfli_BY_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 d5 41 8b 14 24 49 81 c4 04 00 00 00 40 3a e1 41 33 d3 41 f6 c3 98 f7 da e9 } //5
		$a_01_1 = {63 59 72 65 65 6e 51 69 6c 6c 73 73 66 } //1 cYreenQillssf
		$a_01_2 = {76 6d 70 73 30 } //1 vmps0
		$a_01_3 = {76 6d 70 73 31 } //1 vmps1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}