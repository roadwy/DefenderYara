
rule Trojan_Win32_Stealc_ASGH_MTB{
	meta:
		description = "Trojan:Win32/Stealc.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 65 fc 00 83 65 f8 00 8d 4d f8 e8 ?? ?? ?? ?? 8b 45 f8 83 c0 ?? 89 45 fc 83 6d fc ?? 8b 45 08 8a 4d fc 03 c2 30 08 42 3b 55 0c 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}