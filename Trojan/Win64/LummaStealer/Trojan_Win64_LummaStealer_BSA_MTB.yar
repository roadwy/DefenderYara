
rule Trojan_Win64_LummaStealer_BSA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 69 48 8b 48 40 84 01 48 8b 50 48 48 8d 35 b3 04 00 00 48 89 b4 24 } //10
		$a_01_1 = {49 3b 66 10 76 25 55 48 89 e5 48 83 ec 08 4d 8b 66 20 4d 85 e4 75 1b } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_Win64_LummaStealer_BSA_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 e8 9f f6 ?? ?? e8 a6 b9 ff ff 8b c8 48 83 c4 28 } //8
		$a_03_1 = {48 8d 0d 51 42 03 00 e8 08 8d 00 00 85 c0 74 0a [0-16] 00 48 8d 0d 88 41 03 00 e8 a3 8c 00 } //3
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*3) >=11
 
}