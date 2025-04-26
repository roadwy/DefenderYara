
rule Trojan_Win32_QBot_RPA_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 72 69 63 74 69 6f 6e 61 6c 6c 79 00 6d 61 6c 65 64 75 63 61 74 69 6f 6e 00 6d 6f 6c 6f 73 73 69 61 6e 00 6f 70 68 69 63 00 70 61 72 6b 69 6e 67 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}