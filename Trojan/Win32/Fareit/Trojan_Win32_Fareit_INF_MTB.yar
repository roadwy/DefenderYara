
rule Trojan_Win32_Fareit_INF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.INF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 84 ea ff ff 8a 00 8d 0c 8a 03 8d 90 ea ff ff 8b 95 ac ea ff ff 89 8d b4 ea ff ff 8b 8d b8 ea ff ff 88 04 11 41 3b 8d b0 ea ff ff 89 8d b8 ea ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}