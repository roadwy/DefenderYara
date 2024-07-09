
rule Trojan_Win32_CryptInject_YW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 8b e8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b ?? 90 05 0a 01 90 33 ?? 90 05 0a 01 90 8b [0-0a] 3d [0-0f] 8a ?? ?? ?? ?? 00 90 05 0a 01 90 34 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}