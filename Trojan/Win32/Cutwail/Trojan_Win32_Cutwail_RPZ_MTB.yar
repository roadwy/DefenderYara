
rule Trojan_Win32_Cutwail_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 34 6a 40 81 c2 ?? ?? ?? ?? 52 ff 76 60 6a 00 ff d0 89 86 a8 00 00 00 eb 80 33 c0 8b 12 8b c8 8b 72 30 0f be 1c 31 8d 7b bf 83 ff 19 8d 43 20 0f be c0 0f 46 d8 3a 5c 0c 30 75 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}