
rule Trojan_Win32_Remcos_RJ_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 85 c0 89 0c 18 85 db 66 85 ff 4b 66 85 c0 85 c9 4b 85 c0 66 85 c0 4b 85 db 85 c9 4b 7d ?? 85 db 85 c9 ff e0 [0-04] 81 f1 ?? ?? ?? ?? 85 c9 66 85 ff c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}