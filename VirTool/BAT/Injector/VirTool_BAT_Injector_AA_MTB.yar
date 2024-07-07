
rule VirTool_BAT_Injector_AA_MTB{
	meta:
		description = "VirTool:BAT/Injector.AA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 4c 00 2e 00 52 00 75 00 6e 00 50 00 45 00 } //1 CL.RunPE
		$a_01_1 = {5c 00 61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 72 00 65 00 67 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 73 00 2e 00 65 00 78 00 65 00 } //1 \aspnet_regbrowsers.exe
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 敗䍢楬湥t潄湷潬摡慄慴
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 31 00 2e 00 74 00 6f 00 70 00 34 00 74 00 6f 00 70 00 2e 00 6e 00 65 00 74 00 2f 00 } //1 https://1.top4top.net/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}