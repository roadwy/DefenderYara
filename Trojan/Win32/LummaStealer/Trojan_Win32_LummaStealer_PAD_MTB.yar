
rule Trojan_Win32_LummaStealer_PAD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 81 ca 00 fc ff ff 42 8b 44 24 58 89 54 24 2c 88 18 8b 4c 24 14 8b 5c 24 20 8a 04 0a 88 04 0b 8b 44 24 14 8a 4c 24 13 88 0c 02 8b d6 8b 74 24 28 89 54 24 30 81 fa 00 10 00 00 0f 8c } //3
		$a_01_1 = {8b 4c 24 14 8b 7c 24 20 8a 04 0e 88 04 0f 8b 44 24 14 88 14 06 8b d7 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}