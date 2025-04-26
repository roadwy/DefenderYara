
rule Trojan_Win32_LummaC_GNU_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 55 e0 0f b6 02 33 45 dc 8b 4d 14 03 4d e0 88 01 8d 4d e4 } //10
		$a_01_1 = {49 55 41 68 73 69 75 63 68 6e 69 75 6f 68 41 49 55 } //1 IUAhsiuchniuohAIU
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}