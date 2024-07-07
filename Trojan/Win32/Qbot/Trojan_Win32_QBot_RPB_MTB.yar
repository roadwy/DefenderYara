
rule Trojan_Win32_QBot_RPB_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 76 79 6d 61 67 65 65 66 73 2e 64 6c 6c 00 61 69 70 69 6b 67 77 76 6c 69 78 63 63 00 61 70 76 61 68 72 7a 62 73 7a 6d 70 68 71 64 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}