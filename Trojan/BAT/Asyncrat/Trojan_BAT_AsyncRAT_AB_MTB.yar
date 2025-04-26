
rule Trojan_BAT_AsyncRAT_AB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 a6 00 00 0a 1f 20 8d 58 00 00 01 25 d0 8e 01 00 04 28 a7 00 00 0a 28 30 01 00 06 28 a8 00 00 0a 72 3e 27 00 70 72 01 00 00 70 6f a9 00 00 0a } //2
		$a_01_1 = {09 11 04 06 11 04 8f 58 00 00 01 72 70 27 00 70 28 ad 00 00 0a a2 11 04 17 58 13 04 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AsyncRAT_AB_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 6e 00 69 00 63 00 6f 00 64 00 65 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 } //2 [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('
		$a_01_1 = {4f 00 75 00 74 00 2d 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //2 Out-String
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}