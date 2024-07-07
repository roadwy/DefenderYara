
rule VirTool_Win32_Priviadrisz_A_MTB{
	meta:
		description = "VirTool:Win32/Priviadrisz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 8d 90 01 03 50 6a 01 6a 00 6a 00 ff 15 90 01 04 8d 90 00 } //1
		$a_03_1 = {6a 00 6a 00 6a 02 6a 00 6a 00 ff 90 01 01 ff 74 24 18 6a 40 ff 15 90 01 04 8b f8 8d 90 00 } //1
		$a_03_2 = {56 57 50 68 04 cb 41 00 53 ff 15 90 01 04 83 c4 14 89 5c 24 30 53 68 2c cb 41 00 e8 90 01 04 83 c4 08 8d 90 01 03 68 14 80 00 00 50 6a 02 6a 00 ff 15 90 01 04 8b 90 00 } //1
		$a_03_3 = {ff 74 24 20 ff 74 24 28 6a 00 ff 15 90 01 04 50 68 78 cb 41 00 e8 13 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}