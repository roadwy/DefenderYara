
rule Trojan_Win32_Zloader_MKD_MTB{
	meta:
		description = "Trojan:Win32/Zloader.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 a3 ?? ?? ?? ?? 8d ?? d1 1e 00 00 66 89 15 ?? ?? ?? ?? 80 ea 5e 02 d0 0f b6 d2 0f af d1 80 ea 27 88 15 ?? ?? ?? ?? 8b 44 24 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}