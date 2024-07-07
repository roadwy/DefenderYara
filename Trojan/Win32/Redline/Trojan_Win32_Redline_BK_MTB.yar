
rule Trojan_Win32_Redline_BK_MTB{
	meta:
		description = "Trojan:Win32/Redline.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c2 89 d0 ba 58 00 00 00 0f af c2 31 c3 89 d9 8b 55 f0 8b 45 0c 01 d0 89 ca 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}