
rule Trojan_Win32_Sabsik_PJ_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b ed 02 05 66 19 70 1b a8 80 f6 3f a8 a8 f6 3f a0 a8 fe b5 7e 19 8f 22 3b 57 0e 9e 6b ed 89 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}