
rule Trojan_Win32_Conavgent_AAZ_MTB{
	meta:
		description = "Trojan:Win32/Conavgent.AAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ff 8d 74 24 10 c7 44 24 0c ?? ?? ?? ?? c7 44 24 10 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c 46 8a 4c 24 0c 30 0c 2f 83 fb 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}