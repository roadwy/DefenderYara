
rule Trojan_Win32_Sabsik_PJU_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.PJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7c 24 1c 00 74 17 8b d7 2b d3 3b c2 73 0f 83 f8 3c 72 05 83 f8 3e 76 05 c6 01 00 eb 04 8a 16 88 11 41 46 40 ff 4c 24 5c 75 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}