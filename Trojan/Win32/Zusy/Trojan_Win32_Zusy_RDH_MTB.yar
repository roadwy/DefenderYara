
rule Trojan_Win32_Zusy_RDH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 18 83 c0 46 89 44 24 10 90 83 6c 24 10 46 8a 44 24 10 30 04 32 83 bc 24 28 0c 00 00 0f 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}