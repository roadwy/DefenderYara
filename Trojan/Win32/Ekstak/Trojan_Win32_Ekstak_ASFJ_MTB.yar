
rule Trojan_Win32_Ekstak_ASFJ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 01 56 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 6a 00 8d 44 24 18 6a 01 50 c7 44 24 20 0c 00 00 00 89 74 24 24 c7 44 24 28 00 00 00 00 ff 15 } //5
		$a_03_1 = {8d 4c 24 10 8d 54 24 20 51 8b 4c 24 1c 8d 44 24 18 52 50 6a 00 68 ?? ?? 65 00 51 89 6c 24 28 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}