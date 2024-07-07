
rule Trojan_Win32_Cryptinject_PW_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 2b f0 83 c6 04 89 35 90 01 04 8b 84 39 e3 db ff ff 05 60 dd 0e 01 a3 90 01 04 89 84 39 e3 db ff ff 83 c7 04 0f b7 0d 90 01 04 8b 35 90 01 04 8b c1 8a 15 90 01 04 2b c6 83 c0 04 89 45 e8 a3 90 01 04 81 ff fd 24 00 00 72 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}