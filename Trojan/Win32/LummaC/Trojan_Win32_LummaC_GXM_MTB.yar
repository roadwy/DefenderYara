
rule Trojan_Win32_LummaC_GXM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca c1 ea ?? 80 ca ?? 88 16 c1 e9 ?? 89 ca 83 f2 ?? 83 c9 ?? 21 d1 80 c9 ?? 88 4e ?? 80 e3 ?? 80 cb ?? 88 5e ?? b9 03 00 00 00 01 ce } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}