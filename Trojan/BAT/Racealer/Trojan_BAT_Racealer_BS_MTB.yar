
rule Trojan_BAT_Racealer_BS_MTB{
	meta:
		description = "Trojan:BAT/Racealer.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {08 08 1f 3c 58 4b e0 58 25 1c 58 49 0d 25 1f 14 58 49 13 04 16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07 } //10
		$a_80_1 = {75 64 66 69 61 73 64 6b 6b } //udfiasdkk  3
		$a_80_2 = {31 4f 55 54 50 55 54 2d 4f 4e 4c 49 4e 45 50 4e 47 54 4f 4f 4c 53 } //1OUTPUT-ONLINEPNGTOOLS  3
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}