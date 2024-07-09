
rule Trojan_Win32_Tofsee_PVE_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 3e b8 01 00 00 00 29 85 f8 f7 ff ff 8b b5 f8 f7 ff ff 3b f3 7d 90 09 05 00 e8 } //2
		$a_02_1 = {8b 45 fc 8d 34 07 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 45 fc 39 5d fc 7d } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}