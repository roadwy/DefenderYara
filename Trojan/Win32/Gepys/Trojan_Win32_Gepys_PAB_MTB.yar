
rule Trojan_Win32_Gepys_PAB_MTB{
	meta:
		description = "Trojan:Win32/Gepys.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 d8 69 c0 41 c8 04 00 31 da 69 d2 90 01 04 85 db 8d b0 93 b8 00 00 8d 84 00 93 b8 00 00 0f 45 f0 90 00 } //1
		$a_03_1 = {23 7d d4 89 c1 83 c9 01 0f af cb 03 7d 90 01 01 29 c8 03 45 90 01 01 8a 0f ff 4d 90 01 01 88 4d 90 01 01 8a 08 88 0f 8a 4d cb 88 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}