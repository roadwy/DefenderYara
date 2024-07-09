
rule Trojan_Win32_CryptInject_BA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 f1 f0 f0 f0 f7 e6 c1 ea 05 8b c2 c1 e0 04 03 c2 03 c0 8b de 2b d8 8b 44 24 ?? 03 fe 3b 58 ?? 76 ?? e8 ?? ?? ?? ?? 8b 44 24 14 83 78 ?? 10 72 ?? 83 c0 04 8b 00 eb ?? 83 c0 04 8a 0c 18 30 0f 8b 45 ?? 2b 45 ?? 46 3b f0 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}