
rule PWS_Win32_Zbot_R_MTB{
	meta:
		description = "PWS:Win32/Zbot.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 75 79 75 67 69 68 65 70 69 70 69 67 75 64 69 73 69 72 61 62 75 } //1 luyugihepipigudisirabu
		$a_01_1 = {6b 69 6c 6f 76 61 20 78 61 72 75 6a 75 66 75 72 6f 64 65 68 75 68 61 20 6d 6f 76 65 74 6f 6b 65 74 75 6d 6f 64 69 66 65 6a 69 67 65 66 61 } //1 kilova xarujufurodehuha movetoketumodifejigefa
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 73 63 74 } //1 VirtualProtsct
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}