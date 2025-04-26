
rule Trojan_Win32_UrSnif_RPY_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 45 f0 8b 4d 00 8b c6 0d 00 02 00 00 81 e1 00 00 00 04 0f 44 c6 8b f0 8d 44 24 28 50 8b 45 e8 56 ff 75 ec 03 c3 50 ff 54 24 3c 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}