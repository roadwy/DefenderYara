
rule Trojan_Win32_SmokeLoader_RXE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 85 f8 90 01 03 83 c0 64 89 85 f4 90 01 03 83 ad f4 90 01 03 64 8a 8d f4 90 01 03 30 0c 33 83 ff 0f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}