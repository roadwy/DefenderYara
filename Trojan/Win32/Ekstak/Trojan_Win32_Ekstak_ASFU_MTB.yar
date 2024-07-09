
rule Trojan_Win32_Ekstak_ASFU_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec 10 53 56 57 68 ?? 5e 4c 00 e8 ?? ec f5 ff 83 c4 04 89 45 fc } //5
		$a_03_1 = {8b ec 83 ec 10 53 56 57 e8 ?? ?? ?? ff 89 45 f8 e9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}