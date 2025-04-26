
rule Trojan_Win32_DorkBot_RPA_MTB{
	meta:
		description = "Trojan:Win32/DorkBot.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 33 45 f0 03 d0 88 55 ff 8b 4d e8 8a 55 ff 88 94 0d e0 ed ff ff 8b 45 e8 83 c0 01 89 45 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}