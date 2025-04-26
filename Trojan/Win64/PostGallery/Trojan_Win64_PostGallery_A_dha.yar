
rule Trojan_Win64_PostGallery_A_dha{
	meta:
		description = "Trojan:Win64/PostGallery.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 68 65 6c 6c 65 78 65 e9 ?? ?? ?? ?? 48 83 fe 09 0f 85 ?? ?? ?? ?? ?? ?? 73 68 65 6c 6c 65 78 65 } //100
	condition:
		((#a_03_0  & 1)*100) >=100
 
}