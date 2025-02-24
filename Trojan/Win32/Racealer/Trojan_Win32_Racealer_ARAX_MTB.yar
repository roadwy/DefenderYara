
rule Trojan_Win32_Racealer_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Racealer.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 5c 02 04 8a 89 30 73 41 00 32 d9 88 5c 02 04 83 c0 05 3d 40 42 0f 00 0f 8c 5b fd ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}