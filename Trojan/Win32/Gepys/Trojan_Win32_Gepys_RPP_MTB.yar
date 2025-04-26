
rule Trojan_Win32_Gepys_RPP_MTB{
	meta:
		description = "Trojan:Win32/Gepys.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 d9 fe c9 8a 28 20 cd 88 6d fc 85 db 74 07 0f b6 0a 01 c9 eb 03 0f b6 0a 89 4d f8 8a 7d f8 88 38 8a 45 fc 08 d8 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}