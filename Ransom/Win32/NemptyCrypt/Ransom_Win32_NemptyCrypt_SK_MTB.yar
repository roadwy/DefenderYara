
rule Ransom_Win32_NemptyCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/NemptyCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {c7 85 38 ff ff ff 90 01 04 c7 85 90 01 01 fe ff ff 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 fd ff ff 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 fe ff ff 90 01 04 c7 85 90 01 01 fe ff ff 90 01 04 c7 45 90 01 05 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 fe ff ff 90 01 04 c7 85 90 01 01 fe ff ff 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 fd ff ff 90 01 04 c7 85 90 01 01 fd ff ff 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 fd ff ff 90 00 } //2
		$a_02_1 = {55 8b ec 83 ec 90 01 01 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 81 45 90 01 05 81 45 90 01 05 81 6d 90 01 05 81 45 90 01 05 81 45 90 01 05 81 45 90 01 05 81 6d 90 01 05 81 6d 90 01 05 81 45 90 00 } //2
		$a_02_2 = {30 0c 37 83 ee 01 0f 89 90 01 02 ff ff 90 0a 50 00 f7 a5 90 01 01 ff ff ff 8b 85 90 01 01 ff ff ff 81 85 90 01 02 ff ff 90 01 04 81 6d 90 01 05 81 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*1) >=5
 
}