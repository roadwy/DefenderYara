
rule Trojan_Win32_Enjectx_RPX_MTB{
	meta:
		description = "Trojan:Win32/Enjectx.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4e 3c 03 cb 6a 00 ff b4 31 08 01 00 00 8b 84 31 0c 01 00 00 03 c6 50 8b 84 31 04 01 00 00 03 85 9c fb ff ff 50 ff b5 a8 fb ff ff ff 15 90 01 04 8b 8d a0 fb ff ff 83 c3 28 0f b7 47 06 41 89 8d a0 fb ff ff 3b c8 7c b6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}