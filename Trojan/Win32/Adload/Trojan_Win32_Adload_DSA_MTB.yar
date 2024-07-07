
rule Trojan_Win32_Adload_DSA_MTB{
	meta:
		description = "Trojan:Win32/Adload.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 14 11 8b 35 90 01 04 0f b6 3c 35 00 20 90 01 02 89 fb 31 d3 88 1c 35 00 20 90 01 02 81 3d 90 01 04 ff 2b 00 00 0f 83 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}