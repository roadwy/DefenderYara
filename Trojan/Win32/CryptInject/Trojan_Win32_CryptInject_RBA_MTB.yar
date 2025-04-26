
rule Trojan_Win32_CryptInject_RBA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {40 2e eb ed 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 45 ?? 03 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? 76 09 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}