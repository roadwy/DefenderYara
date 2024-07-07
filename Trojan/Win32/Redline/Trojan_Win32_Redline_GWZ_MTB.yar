
rule Trojan_Win32_Redline_GWZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 74 24 20 c1 ea 90 01 01 0f be 5c 15 90 01 01 6b db 57 b8 90 01 04 f7 eb 89 d0 c1 f8 04 c1 fb 1f 29 d8 ba 90 01 04 0f af c2 30 04 0e 83 c1 90 01 01 39 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}