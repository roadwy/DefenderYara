
rule Trojan_Win32_AceLog_B_dha{
	meta:
		description = "Trojan:Win32/AceLog.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 8c 05 90 01 02 ff ff 66 31 8c 05 90 01 02 ff ff 0f b7 8c 05 90 01 02 ff ff 66 31 8c 05 90 01 02 ff ff 0f b7 8c 05 90 01 02 ff ff 66 31 8c 05 90 01 02 ff ff 0f b7 8c 05 90 01 02 ff ff 66 31 8c 05 90 01 02 ff ff 83 c0 08 3d 00 01 00 00 72 b6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}