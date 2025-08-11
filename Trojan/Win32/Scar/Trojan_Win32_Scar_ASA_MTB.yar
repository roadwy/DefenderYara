
rule Trojan_Win32_Scar_ASA_MTB{
	meta:
		description = "Trojan:Win32/Scar.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 60 ea 00 00 e8 ?? ?? ?? ?? 83 ec 04 e8 ?? ?? ?? ?? 50 59 b8 e9 a2 8b 2e f7 e9 d1 fa 51 58 c1 f8 1f 29 c2 52 58 89 45 fc 8b 55 fc 52 58 c1 e0 02 01 d0 d1 e0 01 d0 29 c1 51 58 89 45 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}