
rule Trojan_Win64_Sirefef_AG{
	meta:
		description = "Trojan:Win64/Sirefef.AG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 3d 35 2e 33 26 69 64 3d 25 30 38 78 26 61 69 64 3d 25 75 26 73 69 64 3d 25 75 26 71 3d 25 } //1 v=5.3&id=%08x&aid=%u&sid=%u&q=%
		$a_01_1 = {c7 47 30 63 6e 63 74 48 89 47 28 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_AG_2{
	meta:
		description = "Trojan:Win64/Sirefef.AG,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 3d 35 2e 33 26 69 64 3d 25 30 38 78 26 61 69 64 3d 25 75 26 73 69 64 3d 25 75 26 71 3d 25 } //1 v=5.3&id=%08x&aid=%u&sid=%u&q=%
		$a_01_1 = {c7 47 30 63 6e 63 74 48 89 47 28 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}