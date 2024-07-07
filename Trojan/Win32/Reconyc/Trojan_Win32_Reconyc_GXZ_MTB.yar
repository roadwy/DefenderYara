
rule Trojan_Win32_Reconyc_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f8 0f b6 c0 29 f8 8b bc 85 90 01 04 89 bc 95 90 01 04 89 8c 85 90 01 04 03 8c 95 90 01 04 89 cf c1 ff 90 01 01 c1 ef 90 01 01 01 f9 0f b6 c9 29 f9 8b 8c 8d 90 01 04 8b 7d 90 01 01 32 0c 37 8b bd 90 01 04 88 0c 37 83 c6 90 01 01 39 de 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}