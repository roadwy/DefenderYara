
rule Trojan_Win32_Dialer_MA_MTB{
	meta:
		description = "Trojan:Win32/Dialer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 64 89 25 00 00 00 00 83 ec 38 53 56 57 89 65 e8 83 65 fc 00 c7 45 e4 01 00 00 00 8b 35 e0 10 40 00 ff d6 } //5
		$a_01_1 = {55 54 5d 81 ec b0 01 00 00 53 56 57 6a 24 59 2b c0 8d bd 5c ff ff ff c7 85 58 ff ff ff 94 00 00 00 f3 ab 8d 85 58 ff ff ff 50 ff 15 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}