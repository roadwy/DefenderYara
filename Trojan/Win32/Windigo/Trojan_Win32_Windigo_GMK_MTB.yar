
rule Trojan_Win32_Windigo_GMK_MTB{
	meta:
		description = "Trojan:Win32/Windigo.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 03 cf 03 d3 03 45 90 01 01 81 c3 90 01 04 33 c1 33 c2 29 45 90 01 01 ff 4d 90 01 01 89 45 90 01 01 0f 85 90 01 04 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}