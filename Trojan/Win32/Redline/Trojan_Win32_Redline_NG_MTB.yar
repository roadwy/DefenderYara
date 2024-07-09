
rule Trojan_Win32_Redline_NG_MTB{
	meta:
		description = "Trojan:Win32/Redline.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 45 f8 ba ?? ?? ?? ?? f7 75 14 8b 45 08 01 d0 0f b6 00 ba ?? ?? ?? ?? 0f af c2 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}