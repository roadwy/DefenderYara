
rule VirTool_Win32_Injector_AQ{
	meta:
		description = "VirTool:Win32/Injector.AQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 76 61 73 74 00 50 72 6f 79 65 63 74 6f 31 00 00 50 72 6f 79 65 63 74 6f 31 } //1 癁獡t牐祯捥潴1倀潲敹瑣ㅯ
		$a_01_1 = {5b 00 5b 00 44 00 65 00 6b 00 6f 00 64 00 65 00 72 00 27 00 73 00 5f 00 54 00 65 00 61 00 6d 00 5d 00 5d 00 } //1 [[Dekoder's_Team]]
		$a_01_2 = {4e 65 77 5f 56 61 6c 75 65 00 00 00 50 65 72 63 65 6e 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}