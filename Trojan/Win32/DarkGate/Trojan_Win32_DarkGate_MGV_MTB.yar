
rule Trojan_Win32_DarkGate_MGV_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 69 c1 cb 1d 00 00 b9 ff ff 00 00 2b 44 24 2c 99 f7 fe 8b 54 24 50 66 89 04 7a 8b 44 24 ?? 66 01 08 66 8b 00 0f b7 c8 0f b7 44 7a 0c 8b 54 24 18 3b 04 ca 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}