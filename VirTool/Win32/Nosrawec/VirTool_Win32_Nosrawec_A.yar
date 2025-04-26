
rule VirTool_Win32_Nosrawec_A{
	meta:
		description = "VirTool:Win32/Nosrawec.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 68 40 06 00 00 8d 85 7d f9 ff ff 50 8b 45 ec 50 e8 } //1
		$a_01_1 = {53 63 68 77 61 72 7a 65 20 53 6f 6e 6e 65 20 52 41 54 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}