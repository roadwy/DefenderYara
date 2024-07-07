
rule Trojan_Win32_Ekstak_GJT_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 56 e8 90 01 04 56 6a 00 ff 15 90 01 01 81 65 00 e9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}