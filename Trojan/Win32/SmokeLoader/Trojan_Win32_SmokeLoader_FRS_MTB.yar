
rule Trojan_Win32_SmokeLoader_FRS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 37 1c 8b 45 fc 0f b7 00 8d 04 81 8b 3c 30 83 65 e4 00 8d 45 d8 50 03 fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}