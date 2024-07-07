
rule Backdoor_Win32_Booma_A{
	meta:
		description = "Backdoor:Win32/Booma.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 95 ec fe ff ff 81 e2 ff ff 00 00 81 fa 5a 4d 00 00 74 90 01 01 0f be 85 ee fe ff ff 83 f8 03 74 90 01 01 eb 90 00 } //1
		$a_03_1 = {0f bf 8d ef fe ff ff 89 8d 74 fc ff ff 8b 95 74 fc ff ff 83 ea 04 89 95 74 fc ff ff 83 bd 74 fc ff ff 05 0f 87 90 01 04 8b 85 74 fc ff ff ff 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}