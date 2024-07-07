
rule Trojan_Win32_Scar_NS_MTB{
	meta:
		description = "Trojan:Win32/Scar.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 40 8b 45 90 01 01 89 45 e4 8d 0c c8 6b c9 90 01 01 03 4d 18 6b c9 90 01 01 03 0d 48 95 40 00 4f 90 00 } //5
		$a_03_1 = {e8 8c 10 00 00 8b c3 8d 4b ff 69 c0 90 01 04 c1 f9 02 8b d6 89 75 f8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}