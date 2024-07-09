
rule Trojan_Win32_Upatre_AUP_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 45 20 20 00 6a 6a 30 40 68 68 ?? ?? ?? ?? ec 56 57 8b 7d 0c 33 c0 8b c8 8b 75 08 8a 0e 8a 07 3b c1 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}