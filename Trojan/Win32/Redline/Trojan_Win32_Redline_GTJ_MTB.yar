
rule Trojan_Win32_Redline_GTJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 5c 15 00 6b db 90 01 01 b8 90 01 04 f7 eb 89 d0 c1 f8 90 01 01 c1 fb 90 01 01 29 d8 ba 90 01 04 0f af c2 30 04 0e 83 c1 90 01 01 39 f9 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}