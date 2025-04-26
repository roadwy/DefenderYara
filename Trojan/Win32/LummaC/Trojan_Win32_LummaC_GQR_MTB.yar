
rule Trojan_Win32_LummaC_GQR_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c8 89 c8 83 e1 ?? f7 d0 89 c3 83 e3 ?? 09 d9 31 c8 85 c8 0f 95 c0 0f 94 c4 83 fa ?? 0f 9c c1 83 fa ?? 0f 9f c5 89 ca 08 e1 20 ec 20 c2 30 c5 80 f1 ?? 08 e2 08 e9 b8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}