
rule Trojan_Win32_Convagent_MMZ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.MMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 83 c0 46 89 45 fc 83 6d fc ?? 83 6d fc 3c 8b 45 08 8a 4d fc 03 c7 30 08 47 3b fb 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}