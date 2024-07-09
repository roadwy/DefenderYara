
rule Trojan_Win32_Stealerc_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 83 fe 0a 7c ?? 8b 44 24 ?? 8d 4c 24 ?? 8a 44 04 ?? 30 04 2f e8 ?? ?? ?? ?? 8b 54 24 ?? 47 3b bc 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}