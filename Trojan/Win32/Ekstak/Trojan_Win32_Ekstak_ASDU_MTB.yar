
rule Trojan_Win32_Ekstak_ASDU_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 6a 00 ff 15 ?? ?? 4c 00 8b f0 6a 5a 56 ff 15 ?? ?? 4c 00 56 6a 00 8b f8 ff 15 ?? ?? 4c 00 8b c7 5f 5e 59 c3 } //5
		$a_03_1 = {6a 00 56 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 00 00 cf 10 8d 44 24 2c 68 ?? ?? 4c 00 50 6a 00 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}