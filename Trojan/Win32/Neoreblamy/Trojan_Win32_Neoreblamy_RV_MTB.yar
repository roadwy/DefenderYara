
rule Trojan_Win32_Neoreblamy_RV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 75 0c 8b c2 ba 03 0f 00 00 68 7c 4b 00 00 ff 75 10 68 3e 24 00 00 6a 01 51 68 eb 1b 00 00 ff 75 08 8b c8 68 d3 5c 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}