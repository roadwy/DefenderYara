
rule Trojan_Win32_Redline_FG_MTB{
	meta:
		description = "Trojan:Win32/Redline.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 4d ec 0f be 11 33 d0 a1 04 df 43 00 03 45 ec 88 10 } //1
		$a_01_1 = {33 4c 24 14 33 4c 24 18 2b d9 89 5c 24 24 8b 44 24 44 29 44 24 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}