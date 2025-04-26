
rule Trojan_Win32_Heodo_RPH_MTB{
	meta:
		description = "Trojan:Win32/Heodo.RPH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be c0 83 c4 08 66 0f 6e c8 f3 0f e6 c9 0f 28 c1 f2 0f 5c 45 98 f2 0f 11 45 98 f2 0f 59 c1 f2 0f 2c d8 80 fb 5b 74 c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}