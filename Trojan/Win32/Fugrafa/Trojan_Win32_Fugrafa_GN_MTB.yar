
rule Trojan_Win32_Fugrafa_GN_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0e 32 04 1a 43 88 01 8b 45 e8 3b df 72 ed } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}