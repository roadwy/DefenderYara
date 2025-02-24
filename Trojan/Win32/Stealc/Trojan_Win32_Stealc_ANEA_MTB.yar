
rule Trojan_Win32_Stealc_ANEA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.ANEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f be 04 32 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 bc 24 ?? ?? ?? ?? 0f 8a 4c 24 ?? 88 0c 32 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}