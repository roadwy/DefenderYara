
rule Trojan_Win32_Warzone_MBJB_MTB{
	meta:
		description = "Trojan:Win32/Warzone.MBJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 0f 8b c1 6a 64 99 5f f7 ff 8a 44 14 18 30 04 29 41 81 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}