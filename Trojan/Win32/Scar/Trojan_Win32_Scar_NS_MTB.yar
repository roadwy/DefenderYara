
rule Trojan_Win32_Scar_NS_MTB{
	meta:
		description = "Trojan:Win32/Scar.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 40 8b 45 ?? 89 45 e4 8d 0c c8 6b c9 ?? 03 4d 18 6b c9 ?? 03 0d 48 95 40 00 4f } //5
		$a_03_1 = {e8 8c 10 00 00 8b c3 8d 4b ff 69 c0 ?? ?? ?? ?? c1 f9 02 8b d6 89 75 f8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}