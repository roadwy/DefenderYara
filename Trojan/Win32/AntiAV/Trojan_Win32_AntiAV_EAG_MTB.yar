
rule Trojan_Win32_AntiAV_EAG_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.EAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d7 33 d6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b da 8b 44 24 28 29 44 24 10 83 6c 24 14 01 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}