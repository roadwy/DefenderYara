
rule Trojan_Win32_Fero_SEC_MTB{
	meta:
		description = "Trojan:Win32/Fero.SEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 88 45 ff 88 4d fe 89 55 f8 8b 45 f8 a3 ?? ?? ?? ?? 8a 4d ff 8a 55 fe 30 d1 0f b6 c1 83 c4 08 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}