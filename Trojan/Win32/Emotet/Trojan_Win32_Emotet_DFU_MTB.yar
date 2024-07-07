
rule Trojan_Win32_Emotet_DFU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {45 79 34 72 43 31 62 76 4e 62 66 39 35 44 64 6a 6d 37 75 76 68 71 79 4b 48 36 42 4d 72 73 59 6f 33 48 70 } //1 Ey4rC1bvNbf95Ddjm7uvhqyKH6BMrsYo3Hp
	condition:
		((#a_81_0  & 1)*1) >=1
 
}