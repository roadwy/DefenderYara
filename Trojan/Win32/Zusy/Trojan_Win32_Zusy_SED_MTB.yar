
rule Trojan_Win32_Zusy_SED_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SED!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 41 58 69 4d 4c 38 38 64 72 32 } //2 QAXiML88dr2
		$a_01_1 = {63 00 61 00 6e 00 63 00 72 00 6f 00 20 00 6d 00 61 00 6c 00 65 00 64 00 65 00 74 00 74 00 6f 00 } //2 cancro maledetto
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}