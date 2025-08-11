
rule Trojan_Win32_DllHijack_GTD_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f4 8b 45 f4 3b 45 ec ?? ?? 8b 45 e8 03 45 f4 0f be 00 33 45 f8 89 45 f8 8b 45 f8 0f af 45 e4 89 45 f8 8b 45 f8 c1 e8 07 33 45 f8 89 45 f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}