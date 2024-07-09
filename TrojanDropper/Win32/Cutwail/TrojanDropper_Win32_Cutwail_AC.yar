
rule TrojanDropper_Win32_Cutwail_AC{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff e2 68 00 20 00 00 8f 45 ec } //1
		$a_01_1 = {8d 80 86 00 00 00 83 c0 02 } //1
		$a_03_2 = {31 03 83 e9 02 49 49 7c 08 03 45 ?? 83 c3 04 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}