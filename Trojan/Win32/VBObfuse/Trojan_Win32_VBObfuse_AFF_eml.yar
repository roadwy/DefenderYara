
rule Trojan_Win32_VBObfuse_AFF_eml{
	meta:
		description = "Trojan:Win32/VBObfuse.AFF!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c3 88 06 5e 5b c3 [0-1f] e8 [0-2f] 43 81 fb c2 55 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}