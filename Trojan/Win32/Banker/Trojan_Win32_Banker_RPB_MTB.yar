
rule Trojan_Win32_Banker_RPB_MTB{
	meta:
		description = "Trojan:Win32/Banker.RPB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c7 14 cb 88 01 8b 54 24 10 6b ce 27 89 38 8b c2 2b c1 2b c3 83 c0 04 8d 88 3f ff ff ff 03 ce 81 f9 0e 1d 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}