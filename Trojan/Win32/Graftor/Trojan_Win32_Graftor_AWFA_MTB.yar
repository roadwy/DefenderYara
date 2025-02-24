
rule Trojan_Win32_Graftor_AWFA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.AWFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 81 e6 ff 00 00 00 8a 44 34 ?? 8a d8 03 df 81 e3 ff 00 00 00 8b fb 8a 5c 3c ?? 88 5c 34 ?? 88 44 3c ?? 8a 5c 34 ?? 03 d8 81 e3 ff 00 00 00 8a 44 1c ?? 8a 1c 29 32 c3 88 01 41 4a 75 } //5
		$a_01_1 = {73 74 74 74 64 65 6c 7a 7a 7a 2e 62 61 74 } //1 stttdelzzz.bat
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}