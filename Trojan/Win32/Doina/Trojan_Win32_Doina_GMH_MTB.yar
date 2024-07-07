
rule Trojan_Win32_Doina_GMH_MTB{
	meta:
		description = "Trojan:Win32/Doina.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 d3 80 cb 65 0f bd df 80 75 0c 20 66 0f b6 d9 } //10
		$a_03_1 = {88 04 24 89 44 24 90 01 01 c7 44 24 90 01 01 88 af 81 4a c7 44 24 90 01 01 38 79 fe cc 88 74 24 90 01 01 c6 04 24 45 ff 74 24 90 00 } //10
		$a_01_2 = {2e 76 6d 70 30 } //1 .vmp0
		$a_01_3 = {2e 76 6d 70 31 } //1 .vmp1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}