
rule Trojan_Win64_ReverseShell_HNB_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 72 65 70 72 5f 5f 72 65 76 39 35 73 68 65 6c 6c 5f 75 } //2
		$a_01_1 = {00 54 4d 5f 5f 62 51 38 39 62 61 74 33 68 55 6b 6d 4a 42 34 68 56 68 37 39 62 66 34 77 5f } //1 吀彍扟㡑戹瑡栳歕䩭㑂器㝨戹㑦彷
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}