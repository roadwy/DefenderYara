
rule Trojan_Win32_CobaltStrike_RDD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 0f be 14 10 33 ca a1 90 01 04 8b 50 10 8b 45 fc 88 0c 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}