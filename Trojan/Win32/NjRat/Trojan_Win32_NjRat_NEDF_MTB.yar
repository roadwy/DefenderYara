
rule Trojan_Win32_NjRat_NEDF_MTB{
	meta:
		description = "Trojan:Win32/NjRat.NEDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 18 83 c6 04 88 42 fa 8b c1 c1 e8 10 88 42 fb 8b c1 c1 e8 08 88 42 fc 88 4a fd } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}