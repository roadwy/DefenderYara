
rule Trojan_Win32_Redline_GKP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 c1 e0 03 01 d0 89 c1 8b 55 e8 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 e8 01 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}