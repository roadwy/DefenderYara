
rule Trojan_Win32_Cryptinject_YBB_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.YBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d1 2b 55 e8 89 55 a0 8b 85 64 ff ff ff 33 85 6c ff ff ff 89 85 64 ff ff ff 0f b7 4d ec 0f b6 55 e0 2b ca 89 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}