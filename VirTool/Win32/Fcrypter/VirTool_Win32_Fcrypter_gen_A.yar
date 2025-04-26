
rule VirTool_Win32_Fcrypter_gen_A{
	meta:
		description = "VirTool:Win32/Fcrypter.gen!A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 90 81 3c 24 68 90 83 c4 28 68 74 02 eb ff 68 80 38 90 90 68 83 c0 07 40 68 90 36 8b 03 54 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}