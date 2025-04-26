
rule Trojan_Win32_Fauppod_RX_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 88 4d fe 8a 45 ff 8a 4d fe 30 c8 0f b6 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}