
rule VirTool_Win32_CeeInject_CH{
	meta:
		description = "VirTool:Win32/CeeInject.CH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {36 0f be 14 02 38 d6 74 09 c1 cb 0d 90 03 da 40 eb eb } //1
		$a_01_1 = {68 c0 97 e2 ef } //1
		$a_01_2 = {68 56 87 d9 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}