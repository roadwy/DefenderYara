
rule Trojan_Win32_AprilAxe_D_dha{
	meta:
		description = "Trojan:Win32/AprilAxe.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 03 45 f8 8b 4d 0c 8a 11 88 10 8b 45 f8 83 c0 01 89 45 f8 ?? 4d 0c 83 c1 02 89 4d 0c 8b 55 0c 0f b7 02 85 c0 75 d7 8b 45 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}