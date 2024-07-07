
rule Trojan_Win32_Farfli_BV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 38 80 f1 19 80 c1 7a 88 0c 38 40 3b c6 7c } //2
		$a_01_1 = {5b 45 78 65 63 75 74 65 5d } //1 [Execute]
		$a_01_2 = {4c 65 74 20 6d 65 20 65 78 69 74 } //1 Let me exit
		$a_01_3 = {43 6f 6e 6e 65 63 74 20 4f 4b 21 } //1 Connect OK!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}