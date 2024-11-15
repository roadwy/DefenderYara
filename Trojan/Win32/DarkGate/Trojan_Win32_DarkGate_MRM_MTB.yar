
rule Trojan_Win32_DarkGate_MRM_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 6a ?? 59 f7 f1 8b 44 24 18 8a 4c 14 1c 32 8e ?? ?? ?? ?? 88 0c 06 46 3b 74 24 ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}