
rule Trojan_Win32_LummaC_GNT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 40 00 00 c0 2e 69 64 61 ?? 61 20 20 00 10 00 00 00 } //5
		$a_01_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 fc 02 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win32_LummaC_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 44 05 00 00 00 60 00 00 00 06 00 00 00 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 } //10
		$a_01_1 = {64 00 65 00 66 00 4f 00 66 00 66 00 2e 00 65 00 78 00 65 00 00 00 00 00 48 00 12 00 } //1
		$a_80_2 = {64 65 66 4f 66 66 2e 65 78 65 } //defOff.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}