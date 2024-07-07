
rule Trojan_Win32_Shifu_A_MTB{
	meta:
		description = "Trojan:Win32/Shifu.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 89 d3 66 2b 90 01 02 66 09 df 2b 45 90 00 } //2
		$a_03_1 = {01 d1 8b b4 24 90 01 04 31 c6 89 b4 24 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}