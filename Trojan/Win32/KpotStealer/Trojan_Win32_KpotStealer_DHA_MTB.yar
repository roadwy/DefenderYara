
rule Trojan_Win32_KpotStealer_DHA_MTB{
	meta:
		description = "Trojan:Win32/KpotStealer.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {e8 4b fd ff ff 8b 4c 24 04 30 04 0e b8 01 00 00 00 83 f0 04 83 6c 24 04 01 83 7c 24 04 00 7d } //1
		$a_02_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 a1 90 01 04 0f b6 80 90 01 04 03 05 90 01 04 25 ff 00 00 00 81 3d 90 01 04 21 06 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}