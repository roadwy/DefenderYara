
rule Trojan_Win32_Staser_GKU_MTB{
	meta:
		description = "Trojan:Win32/Staser.GKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 e0 0f 33 c2 0f b6 db 33 c3 83 f8 72 75 90 01 01 33 c0 5b 5e c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}