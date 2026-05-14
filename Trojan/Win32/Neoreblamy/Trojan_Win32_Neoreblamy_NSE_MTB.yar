
rule Trojan_Win32_Neoreblamy_NSE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 2e 83 65 e8 00 eb 07 8b 45 e8 40 89 45 e8 81 7d e8 } //1
		$a_01_1 = {d3 e6 8b 45 c4 99 f7 7d bc 8b ca d3 e6 8b c6 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}