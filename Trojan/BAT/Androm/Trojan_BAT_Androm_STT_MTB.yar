
rule Trojan_BAT_Androm_STT_MTB{
	meta:
		description = "Trojan:BAT/Androm.STT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 00 73 00 2f 00 36 00 68 00 4f 00 41 00 41 00 76 00 45 00 32 00 78 00 4e 00 65 00 79 00 79 00 78 00 4d 00 34 00 4f 00 44 00 41 00 3d 00 3d 00 } //2 4s/6hOAAvE2xNeyyxM4ODA==
		$a_01_1 = {4c 00 69 00 70 00 61 00 71 00 69 00 69 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Lipaqii.Properties.Resources
		$a_01_2 = {44 00 68 00 6a 00 65 00 6b 00 68 00 6c 00 61 00 } //1 Dhjekhla
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}