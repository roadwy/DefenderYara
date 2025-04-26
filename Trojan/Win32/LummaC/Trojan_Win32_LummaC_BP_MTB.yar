
rule Trojan_Win32_LummaC_BP_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 88 45 ff 0f b6 4d ff 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 e9 } //4
		$a_01_1 = {f7 f6 03 ca 0f b6 c1 5e 5d c3 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}