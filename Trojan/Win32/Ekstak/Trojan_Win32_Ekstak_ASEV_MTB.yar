
rule Trojan_Win32_Ekstak_ASEV_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 14 c7 44 24 10 00 00 00 00 51 56 c7 44 24 14 00 00 00 00 c7 44 24 10 04 00 00 00 ff 15 ?? ?? ?? 00 8b 4c 24 04 8b f0 8d 54 24 08 8d 44 24 10 52 50 6a 00 6a 00 68 ?? ?? ?? 00 51 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}