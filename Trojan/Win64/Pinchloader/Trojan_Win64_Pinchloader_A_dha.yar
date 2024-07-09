
rule Trojan_Win64_Pinchloader_A_dha{
	meta:
		description = "Trojan:Win64/Pinchloader.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 3d 30 cf 38 00 74 ?? f3 0f 6f 4c 06 f0 f3 0f 6f 14 06 66 0f ef c8 66 0f ef d0 f3 0f 7f 4c 06 f0 f3 0f 7f 14 06 48 83 c0 40 } //1
		$a_01_1 = {22 e1 0e 76 4a 22 e1 26 76 52 05 07 19 08 22 dd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}