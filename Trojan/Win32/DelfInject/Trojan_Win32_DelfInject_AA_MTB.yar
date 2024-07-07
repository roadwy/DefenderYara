
rule Trojan_Win32_DelfInject_AA_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 00 89 85 b4 fe ff ff 8b 85 cc fe ff ff 8b 04 85 6c 26 5f 00 89 85 b8 fe ff ff b8 d8 a5 59 00 89 85 bc fe ff ff 8b 85 cc fe ff ff 8b 04 85 6c 36 5f 00 31 d2 89 85 a8 fe ff ff 89 95 ac fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}