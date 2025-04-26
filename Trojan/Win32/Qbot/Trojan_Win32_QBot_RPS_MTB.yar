
rule Trojan_Win32_QBot_RPS_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 74 68 79 72 69 64 61 65 00 66 61 74 69 6c 00 66 65 6c 74 6d 6f 6e 67 65 72 00 66 6f 72 65 6d 69 73 67 69 76 69 6e 67 00 6a 75 6d 61 6e 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}