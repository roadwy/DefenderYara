
rule Trojan_Win32_GhostRAT_SPVX_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.SPVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 69 6d 67 73 76 63 } //2 SystemRoot%\System32\svchost.exe -k imgsvc
		$a_81_1 = {4d 73 62 66 6a 73 20 47 76 74 75 72 75 78 6b 20 4a 6b 6c } //2 Msbfjs Gvturuxk Jkl
		$a_81_2 = {56 70 6b 71 5c 42 69 78 61 73 6e 62 77 70 2e 70 69 63 } //1 Vpkq\Bixasnbwp.pic
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}