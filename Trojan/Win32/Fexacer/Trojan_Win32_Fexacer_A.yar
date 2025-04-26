
rule Trojan_Win32_Fexacer_A{
	meta:
		description = "Trojan:Win32/Fexacer.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7b 42 43 35 42 39 32 42 45 2d 45 41 31 34 2d 34 65 30 61 2d 39 35 41 33 2d 38 37 46 38 30 43 30 32 42 39 38 37 7d 5f } //1 {BC5B92BE-EA14-4e0a-95A3-87F80C02B987}_
		$a_01_1 = {2e 31 31 38 66 6f 78 2e 63 6f 6d 2e 63 6e 2f } //1 .118fox.com.cn/
		$a_01_2 = {26 70 6f 70 5f 72 75 6c 65 5f 69 64 3d } //1 &pop_rule_id=
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 61 63 41 64 64 72 65 73 73 } //1 Software\Microsoft\MacAddress
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}