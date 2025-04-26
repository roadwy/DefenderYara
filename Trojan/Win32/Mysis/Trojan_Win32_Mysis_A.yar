
rule Trojan_Win32_Mysis_A{
	meta:
		description = "Trojan:Win32/Mysis.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 64 6f 73 2e 74 66 } //1 ddos.tf
		$a_01_1 = {69 6e 76 65 73 74 2e 66 33 33 32 32 2e 6e 65 74 } //1 invest.f3322.net
		$a_01_2 = {57 69 6e 64 6f 77 73 20 48 65 6c 70 20 53 79 73 74 65 6d 20 4d 79 73 73 } //1 Windows Help System Myss
		$a_03_3 = {6a 12 56 53 e8 ?? ?? ?? ?? c6 85 ?? ?? ff ff 47 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 77 c6 85 ?? ?? ff ff 73 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}