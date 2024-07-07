
rule Trojan_Win32_DelfInject_MBFE_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.MBFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 00 66 00 6a 00 67 00 6f 00 61 00 66 00 67 00 6e 00 6b 00 6c 00 63 00 71 00 76 00 6f 00 61 00 7a 00 6b 00 64 00 6b 00 70 00 6f 00 62 00 68 00 62 00 65 00 6c 00 6a 00 70 00 79 00 68 00 76 00 67 00 78 00 69 00 } //1 ifjgoafgnklcqvoazkdkpobhbeljpyhvgxi
		$a_01_1 = {18 53 40 00 98 11 40 00 10 f2 70 00 00 ff ff ff 08 00 00 00 01 00 00 00 0c 00 00 00 e9 00 00 00 98 29 40 00 dc 10 40 00 a0 10 40 00 78 00 00 00 7d 00 00 00 80 } //1
		$a_01_2 = {6f 7a 69 6f 00 63 6d 00 00 46 69 65 73 74 61 73 00 00 00 00 f4 01 00 00 b0 54 40 00 00 00 00 00 c0 be 44 00 d0 be 44 00 2c 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}