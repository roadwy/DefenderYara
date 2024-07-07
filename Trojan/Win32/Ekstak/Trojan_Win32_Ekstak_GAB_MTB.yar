
rule Trojan_Win32_Ekstak_GAB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 e2 17 7b 90 01 01 59 7c 90 01 01 00 00 be 90 01 04 49 b9 90 01 04 00 dc 01 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}