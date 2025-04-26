
rule Trojan_Win32_Ekstak_ASEM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 be 0a 00 df 2d d6 87 ?? ?? ?? 00 00 d4 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}