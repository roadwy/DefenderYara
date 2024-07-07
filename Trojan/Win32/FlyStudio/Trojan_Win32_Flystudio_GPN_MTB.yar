
rule Trojan_Win32_Flystudio_GPN_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 e0 04 c1 eb 03 32 d8 c1 e9 05 8a c2 c0 e0 02 32 c8 8b 45 f8 02 d9 83 e0 03 8b 4d 08 33 c6 8a 0c 81 32 4d fc 8a 45 f4 32 c2 02 c8 32 d9 8b 4d f8 00 1c 39 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}