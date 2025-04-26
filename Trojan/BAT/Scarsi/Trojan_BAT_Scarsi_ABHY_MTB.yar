
rule Trojan_BAT_Scarsi_ABHY_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.ABHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 02 08 18 6f 2b 00 00 0a 1f 10 28 2c 00 00 0a 6f 2d 00 00 0a 08 18 58 0c 08 06 32 e3 07 6f 2e 00 00 0a 2a } //2
		$a_01_1 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}