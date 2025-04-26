
rule Trojan_Win32_LummaStealer_MC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 85 fc eb ff ff 89 4d 10 2b f0 8d 85 f8 eb ff ff 6a 00 50 56 8d 85 fc eb ff ff 50 57 ff 15 } //5
		$a_01_1 = {2e 76 75 69 61 33 } //2 .vuia3
		$a_01_2 = {5f 47 65 74 50 68 79 73 69 63 61 6c 53 69 7a 65 40 31 32 } //2 _GetPhysicalSize@12
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}