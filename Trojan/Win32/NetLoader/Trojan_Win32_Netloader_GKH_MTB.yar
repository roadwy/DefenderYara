
rule Trojan_Win32_Netloader_GKH_MTB{
	meta:
		description = "Trojan:Win32/Netloader.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 85 68 f9 ff ff 49 c6 85 69 f9 ff ff 6e c6 85 6a f9 ff ff 74 c6 85 6b f9 ff ff 65 c6 85 6c f9 ff ff 72 c6 85 6d f9 ff ff 6e c6 85 6e f9 ff ff 65 c6 85 6f f9 ff ff 74 c6 85 70 f9 ff ff 52 c6 85 71 f9 ff ff 65 c6 85 72 f9 ff ff 61 c6 85 73 f9 ff ff 64 c6 85 74 f9 ff ff 46 c6 85 75 f9 ff ff 69 c6 85 76 f9 ff ff 6c c6 85 77 f9 ff ff 65 c6 85 78 f9 ff ff 00 6a 00 6a 00 6a 00 6a 00 8d 8d 90 01 04 51 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}