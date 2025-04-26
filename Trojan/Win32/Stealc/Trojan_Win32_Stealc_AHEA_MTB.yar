
rule Trojan_Win32_Stealc_AHEA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AHEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 6c 24 14 46 8b 4c 24 ?? 0f be 14 39 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b b4 24 ?? ?? ?? ?? 8a 44 24 ?? 88 04 39 83 fe 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}