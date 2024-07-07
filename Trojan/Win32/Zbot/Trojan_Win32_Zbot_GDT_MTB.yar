
rule Trojan_Win32_Zbot_GDT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 45 00 32 c3 89 75 18 24 03 30 45 00 83 fb 01 } //10
		$a_01_1 = {61 75 6c 62 62 69 77 73 6c 78 70 76 76 70 68 78 6e 6a 69 6a 2e 62 69 7a } //1 aulbbiwslxpvvphxnjij.biz
		$a_80_2 = {6d 69 63 72 73 6f 6c 76 } //micrsolv  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}