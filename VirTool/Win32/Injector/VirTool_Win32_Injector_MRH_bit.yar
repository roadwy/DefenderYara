
rule VirTool_Win32_Injector_MRH_bit{
	meta:
		description = "VirTool:Win32/Injector.MRH!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 65 74 73 45 76 6e 74 } //1 ResetsEvnt
		$a_01_1 = {50 6f 77 65 72 53 68 65 6c 6c 54 68 65 20 53 74 61 72 74 45 6c 65 6d 65 6e 74 } //1 PowerShellThe StartElement
		$a_01_2 = {ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a } //1
		$a_01_3 = {b6 08 66 d1 eb 66 d1 d8 73 09 66 35 20 83 66 81 f3 b8 ed fe ce 75 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}