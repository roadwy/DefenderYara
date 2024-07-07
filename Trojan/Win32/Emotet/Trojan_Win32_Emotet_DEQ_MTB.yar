
rule Trojan_Win32_Emotet_DEQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 cb 03 c1 99 b9 55 02 00 00 f7 f9 83 c4 38 45 0f b6 54 14 18 30 55 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}