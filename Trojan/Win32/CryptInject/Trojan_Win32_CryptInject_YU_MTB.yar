
rule Trojan_Win32_CryptInject_YU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 fc b8 ?? ?? 00 00 e8 ?? ?? ?? ff 8b ?? 90 05 0a 01 90 33 ?? 90 05 0a 01 90 8b [0-0a] 8a ?? ?? ?? ?? 00 90 05 0a 01 90 80 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}