
rule Trojan_Win32_LummaStealer_PAB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 54 24 2c 88 18 8b 4c 24 14 8b 5c 24 20 8a 04 0a 88 04 0b 8b 44 24 14 8a 4c 24 13 88 0c 02 8b d6 8b 74 24 28 89 54 24 30 81 fa 00 10 00 00 } //3
		$a_01_1 = {32 0c 07 8b 44 24 18 32 0c 07 32 0b 32 4c 24 12 8b 44 24 74 88 0b 8b 4c 24 6c } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}