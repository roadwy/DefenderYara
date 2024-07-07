
rule Trojan_Win32_Qukart_GMD_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 48 48 75 4a 50 71 44 } //1 xHHuJPqD
		$a_01_1 = {4b 42 65 57 6a 45 70 62 40 } //1 KBeWjEpb@
		$a_01_2 = {75 52 54 52 79 50 53 46 } //1 uRTRyPSF
		$a_01_3 = {70 66 4e 71 4b 74 71 65 } //1 pfNqKtqe
		$a_01_4 = {46 4b 6e 65 45 57 6b 6c } //1 FKneEWkl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}