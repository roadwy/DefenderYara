
rule Trojan_Win64_Redline_GNK_MTB{
	meta:
		description = "Trojan:Win64/Redline.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b c1 66 89 44 24 4e 69 c0 ?? ?? ?? ?? 48 ff c3 2b c1 88 44 1c 4f 48 83 fb 08 } //10
		$a_80_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 53 79 73 74 65 6d 53 65 72 76 69 63 65 73 54 6f 6f 6c 73 22 20 2f 74 72 } //schtasks /create /tn "SystemServicesTools" /tr  1
		$a_01_2 = {31 00 37 00 36 00 2e 00 31 00 31 00 31 00 2e 00 31 00 37 00 34 00 2e 00 31 00 34 00 30 00 2f 00 61 00 70 00 69 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}