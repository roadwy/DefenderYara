
rule Trojan_Win32_NetWire_MA_MTB{
	meta:
		description = "Trojan:Win32/NetWire.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 74 14 8b 0c 17 88 ae 86 e8 9f 82 1b 76 04 82 1d 75 12 af 06 6e 21 ce 9c 7c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}