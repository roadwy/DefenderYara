
rule Trojan_Win32_Malgent_BS_MTB{
	meta:
		description = "Trojan:Win32/Malgent.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 10 8d 52 01 80 f1 c0 80 e9 15 80 f1 e2 88 4a ff 83 ee 01 75 } //2
		$a_01_1 = {4a 75 6d 70 4c 6f 67 69 6e } //1 JumpLogin
		$a_01_2 = {52 75 6e 53 65 72 76 69 63 65 } //1 RunService
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}