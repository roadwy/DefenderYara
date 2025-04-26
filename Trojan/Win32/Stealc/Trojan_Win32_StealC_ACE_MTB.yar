
rule Trojan_Win32_StealC_ACE_MTB{
	meta:
		description = "Trojan:Win32/StealC.ACE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 46 89 44 24 04 83 6c 24 04 46 8a 4c 24 04 30 0c 33 83 ff 0f 75 ?? 6a 00 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}