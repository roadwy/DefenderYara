
rule Trojan_Win32_StealC_SPFF_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 74 24 10 c7 44 24 0c ?? ?? ?? ?? c7 44 24 10 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c 0a 90 90 83 6c 24 0c 3c 8a 44 24 0c 30 04 2f 83 fb 0f 75 0b 8b 4c 24 10 51 ff 15 ?? ?? ?? ?? 47 3b fb 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}