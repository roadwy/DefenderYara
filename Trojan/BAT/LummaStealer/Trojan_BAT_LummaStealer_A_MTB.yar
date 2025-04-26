
rule Trojan_BAT_LummaStealer_A_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 ff a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b2 00 00 00 81 01 00 00 e1 05 00 00 f9 06 00 00 d5 05 } //2
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_2 = {4f 70 65 6e 53 75 62 4b 65 79 } //1 OpenSubKey
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_LummaStealer_A_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 17 58 17 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? ?? 03 08 19 58 18 59 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 19 58 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 1a 58 19 59 6e 5a 31 b1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}