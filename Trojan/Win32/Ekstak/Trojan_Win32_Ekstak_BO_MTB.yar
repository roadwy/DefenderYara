
rule Trojan_Win32_Ekstak_BO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 68 28 eb 46 00 ff 15 90 02 04 e9 90 00 } //5
		$a_01_1 = {55 8b ec 83 ec 0c 53 56 57 8b 45 14 50 e8 b2 53 04 00 e9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}