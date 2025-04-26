
rule Trojan_Win32_QBot_RPX_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 10 0c 5a 1c 71 62 09 1c 71 62 09 1c 71 62 09 61 08 be 09 6a 71 62 09 73 07 fc 09 18 71 62 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}