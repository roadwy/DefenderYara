
rule Trojan_Win32_Ekstak_BQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 50 e8 90 01 02 04 00 a1 00 90 01 02 00 6a 00 ff d0 e9 90 00 } //5
		$a_01_1 = {55 8b ec 56 ff 15 9c c2 46 00 e9 } //5
		$a_03_2 = {55 8b ec 56 8b 75 14 56 ff 15 00 90 01 01 46 00 56 e8 90 02 04 e9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}