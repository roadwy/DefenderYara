
rule Trojan_Win32_Loyeetro_DSK_MTB{
	meta:
		description = "Trojan:Win32/Loyeetro.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 54 08 03 88 55 fe 8a 45 fe 88 45 ff c0 65 ff 02 0f b6 4d ff 81 e1 c0 00 00 00 88 4d ff 0f b6 55 fd 0f b6 45 ff 0b d0 88 55 fd } //00 00 
	condition:
		any of ($a_*)
 
}