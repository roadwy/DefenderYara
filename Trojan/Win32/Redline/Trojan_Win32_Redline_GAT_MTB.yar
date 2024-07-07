
rule Trojan_Win32_Redline_GAT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f0 33 f3 8b f6 33 f0 8b f6 8b de 8b de 33 f6 33 c6 80 07 87 8b c6 8b c0 8b db 8b f0 33 c0 8b f0 8b c0 8b c0 8b de 80 2f 54 8b de 33 db 8b c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}