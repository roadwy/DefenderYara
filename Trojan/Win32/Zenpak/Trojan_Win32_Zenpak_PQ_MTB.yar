
rule Trojan_Win32_Zenpak_PQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 0c 8a 4d 08 30 c8 8b 15 f8 fa 33 10 81 c2 36 ed ff ff 89 15 f4 fa 33 10 0f b6 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}