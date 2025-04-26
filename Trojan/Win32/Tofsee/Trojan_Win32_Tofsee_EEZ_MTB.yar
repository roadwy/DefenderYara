
rule Trojan_Win32_Tofsee_EEZ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8d 75 f8 89 7d f8 e8 ?? ?? ?? ?? 8b 4d fc 8b 45 08 8b 75 0c 03 c1 8a 4d f8 30 08 83 fe 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}