
rule Trojan_Win32_Fragtor_DB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 05 ?? ?? ?? ?? 0f b6 00 8b 55 f4 81 c2 ?? ?? ?? ?? 88 02 83 45 f4 01 8b 55 b0 8b 45 ac 01 d0 01 45 f0 8b 45 f0 3d ff 57 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}