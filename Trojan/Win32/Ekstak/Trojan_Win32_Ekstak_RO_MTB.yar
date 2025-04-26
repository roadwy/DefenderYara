
rule Trojan_Win32_Ekstak_RO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 68 ef de 64 00 e8 45 6f fb ff 8b f0 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RO_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 68 53 ff 64 00 e8 b5 71 fb ff 8b f0 e9 } //5
		$a_00_1 = {56 68 2f df 64 00 e8 c5 71 fb ff 8b f0 e9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*5) >=5
 
}
rule Trojan_Win32_Ekstak_RO_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 68 01 ef 64 00 e8 a5 71 fb ff 8b f0 e9 } //5
		$a_01_1 = {56 e8 ca 71 fb ff 8b f0 e9 } //5
		$a_01_2 = {40 00 00 40 2e 74 61 62 6c 65 } //1 @䀀琮扡敬
		$a_01_3 = {40 00 00 40 5f 74 61 62 6c 65 5f } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule Trojan_Win32_Ekstak_RO_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? fe f5 ff 89 45 fc e9 } //1
		$a_01_1 = {55 8b ec 83 ec 0c 53 56 57 68 c8 32 4c 00 e8 6d fe f5 ff 83 c4 04 89 45 fc e9 } //1
		$a_01_2 = {46 00 6c 00 61 00 70 00 70 00 69 00 6e 00 67 00 57 00 69 00 6e 00 67 00 73 00 } //5 FlappingWings
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}