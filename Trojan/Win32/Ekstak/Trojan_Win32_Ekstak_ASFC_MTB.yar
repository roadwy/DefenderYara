
rule Trojan_Win32_Ekstak_ASFC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 4a 56 ff d7 5f eb ?? 68 ?? ?? 65 00 6a 01 6a 00 ff 15 ?? ?? 65 00 85 c0 } //5
		$a_03_1 = {55 8b ec 81 ec ac 01 00 00 53 56 57 8d 85 ?? ?? ff ff 50 68 02 02 00 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}
rule Trojan_Win32_Ekstak_ASFC_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.ASFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec 08 56 68 ?? ?? 65 00 e8 5f } //5
		$a_01_1 = {57 00 61 00 6b 00 3f 00 58 00 62 00 6c 00 40 00 59 00 63 00 6d 00 41 00 5a 00 64 00 6e 00 42 00 5b 00 65 00 6f 00 43 00 5c 00 66 00 70 00 44 00 5d 00 67 00 71 } //-10
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*-10) >=5
 
}