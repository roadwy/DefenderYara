
rule Trojan_Win64_IcedID_MAY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 6a 79 68 67 73 61 64 61 66 67 68 6a 68 6b 6a 67 67 61 } //10 ujyhgsadafghjhkjgga
		$a_01_1 = {f0 00 22 20 0b 02 02 0e 00 90 00 00 00 b4 05 00 00 00 00 00 00 00 00 00 00 10 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}