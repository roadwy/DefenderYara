
rule Trojan_BAT_Redline_NEBE_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 13 05 11 05 17 58 13 04 11 04 07 8e 69 3f d8 ff ff ff 09 6f ?? 00 00 0a 13 06 } //10
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 36 38 } //1 WindowsFormsApp68
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}