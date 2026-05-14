
rule Trojan_Win32_Convagent_TON_MTB{
	meta:
		description = "Trojan:Win32/Convagent.TON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 0f b6 84 3d f8 fe ff ff 88 84 35 f8 fe ff ff 88 8c 3d f8 fe ff ff 0f b6 84 35 f8 fe ff ff 8b 4d f8 03 c2 0f b6 c0 0f b6 84 05 f8 fe ff ff 30 04 19 43 3b 5d fc 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}