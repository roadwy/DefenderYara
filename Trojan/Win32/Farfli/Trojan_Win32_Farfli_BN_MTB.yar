
rule Trojan_Win32_Farfli_BN_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75 } //1
		$a_01_1 = {66 75 63 6b 79 6f 75 } //1 fuckyou
		$a_01_2 = {77 77 77 2e 6a 69 6e 6a 69 6e 2e 63 6f 6d } //1 www.jinjin.com
		$a_01_3 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
		$a_01_4 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d } //1 [Scroll Lock]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}