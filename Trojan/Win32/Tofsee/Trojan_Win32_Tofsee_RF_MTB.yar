
rule Trojan_Win32_Tofsee_RF_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 85 fb fb ff ff 24 c0 0a c8 8a c2 c0 e0 06 80 e2 fc 88 85 fb fb ff ff 0a e8 8b 85 ec fb ff ff c0 e2 04 0a d3 88 0c 06 88 54 06 01 83 c6 02 88 2c 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}