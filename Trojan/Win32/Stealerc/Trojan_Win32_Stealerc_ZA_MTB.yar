
rule Trojan_Win32_Stealerc_ZA_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0d ec d9 45 00 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ec d9 45 00 8a 15 ee d9 45 00 30 14 1e 83 ff 0f 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}