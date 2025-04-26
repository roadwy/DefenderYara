
rule Trojan_Win32_Neoreblamy_BQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 da 1b d2 33 c9 f7 da 3b d0 8b 45 } //5
		$a_03_1 = {33 d2 8b ce 2b c8 8b 45 ?? 3b c8 8b 45 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}