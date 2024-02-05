
rule Trojan_Win32_Astaroth_psyN_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {83 c4 18 8b 85 7c fe ff ff 39 45 dc 0f 8f a9 03 00 00 68 80 3a 40 00 68 70 3a 40 00 e8 41 0f 00 00 8b d0 8d 8d 68 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}