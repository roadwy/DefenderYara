
rule Trojan_Win32_Gozi_RPY_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 04 00 00 80 3f c7 04 24 00 00 00 00 ff d0 51 51 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 80 3f c7 04 24 00 00 00 00 ff d6 83 ec 0c c7 44 24 04 00 00 00 bf c7 04 24 52 b8 5e 3f ff 55 80 50 50 c7 44 24 08 00 00 80 3f c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}