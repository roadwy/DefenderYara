
rule Trojan_Win32_Tofsee_PVR_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 8b 5c 24 ?? 03 4c 24 ?? 03 dd a1 ?? ?? ?? ?? 89 4c 24 10 3d 72 05 00 00 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}